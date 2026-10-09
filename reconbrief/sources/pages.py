"""Page loader: the root page of up to 50 live hosts, read through the address guard.

No crawl. For each host it reads robots.txt, loads "/" once if robots allows it, and records
what the response showed: status, title, banners, certificate, and the signals later rules use.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from urllib.robotparser import RobotFileParser

from reconbrief.http import USER_AGENT, Fetch
from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.certinfo import parse_certificate
from reconbrief.sources.common import health_from, in_scope, make_evidence
from reconbrief.sources.dns_records import M365_NAMES, points_to_microsoft
from reconbrief.sources.htmlsignals import parse_html
from reconbrief.sources.patterns import extract_banners, find_certifications, find_vendors

MAX_PAGE_HOSTS = 50
ROBOTS_BYTES = 200_000
PAGE_BYTES = 1_000_000
WORKERS = 8

ERROR_CLASSES = {
    "unresolved": "dns_no_address",
    "dns_unknown": "dns_failed",
    "blocked_address": "internal_address",
    "blocked_port": "blocked_port",
    "bad_url": "bad_url",
    "timeout": "timeout",
    "connect_failed": "connection_refused_or_unreachable",
    "tls_failed": "tls_handshake_failed",
    "read_failed": "connection_dropped",
    "too_many_redirects": "redirect_loop",
}


def classify(fetch: Fetch) -> str:
    """One word for how a fetch ended: ok, redirect, client_error, server_error, or a network error class."""
    if fetch.error:
        return ERROR_CLASSES.get(fetch.error, fetch.error)
    status = fetch.status or 0
    if 200 <= status < 300:
        return "ok"
    if 300 <= status < 400:
        return "redirect"
    if 400 <= status < 500:
        return "client_error"
    return "server_error"


def charset_of(fetch: Fetch) -> str:
    match = re.search(r"charset=([\w-]+)", fetch.header("content-type") or "", re.I)
    return match.group(1) if match else "utf-8"


def is_html(fetch: Fetch) -> bool:
    ctype = (fetch.header("content-type") or "").lower()
    return "html" in ctype or (not ctype and fetch.body.lstrip()[:15].lower().startswith((b"<!doctype", b"<html")))


def select_hosts(ctx: Context) -> tuple[list[str], int, bool]:
    """Hosts to load, in order: the domain, www, hosts that differ from the wildcard, wildcard hosts last.

    Only hosts with DNS addresses are loaded. Microsoft 365 service names that point at Microsoft are
    skipped, since they are Microsoft's servers. Returns (hosts, skipped_m365, capped)."""
    live: dict[str, dict] = {}
    for ev in ctx.evidence:
        if ev.kind == "host_dns" and ev.state is Tri.FOUND and ev.data.get("addresses") \
                and in_scope(ev.subject, ctx.domain):
            live[ev.subject] = ev.data
    m365 = {e.subject for e in ctx.evidence if e.kind == "m365_name" and e.data.get("points_to_microsoft")}
    skipped = 0
    for host in list(live):
        label = host.split(".")[0]
        if host in m365 or (label in M365_NAMES and points_to_microsoft(live[host].get("chain", []))):
            del live[host]
            skipped += 1
    apex_www = [ctx.domain, f"www.{ctx.domain}"]
    rest = sorted(h for h in live if h not in apex_www)
    normal = [h for h in rest if live[h].get("matches_wildcard") is not True]
    wildcard = [h for h in rest if live[h].get("matches_wildcard") is True]
    ordered = [h for h in apex_www if h in live or h == ctx.domain] + normal + wildcard
    # Seed hosts are always tried: the domain itself, even when discovery found no address for it.
    ordered = list(dict.fromkeys(ordered))
    return ordered[:MAX_PAGE_HOSTS], skipped, len(ordered) > MAX_PAGE_HOSTS


def robots_policy(ctx: Context, host: str) -> tuple[Tri, RobotFileParser | None, str, bool]:
    """(state, parser, note, allowed). ABSENT means the server answered that there is no robots.txt.
    UNKNOWN means it could not be read: a server error means stay out (RFC 9309); a network error
    does not hide the page, since the page fetch will show the host's trouble."""
    fetch = ctx.http.fetch(f"https://{host}/robots.txt", max_bytes=ROBOTS_BYTES)
    parser = RobotFileParser()
    if fetch.ok and fetch.status == 200:
        parser.parse(fetch.body.decode("utf-8", "replace").splitlines())
        return Tri.FOUND, parser, "", parser.can_fetch(USER_AGENT, "/")
    if fetch.ok and 400 <= fetch.status < 500:
        return Tri.ABSENT, None, "", True
    if fetch.ok:
        return Tri.UNKNOWN, None, f"robots.txt returned HTTP {fetch.status}", False
    return Tri.UNKNOWN, None, f"robots.txt not read ({fetch.error})", True


def load_root(ctx: Context, host: str) -> tuple[Fetch, str]:
    """HTTPS first; plain HTTP only when HTTPS could not be reached at all."""
    https = ctx.http.fetch(f"https://{host}/", max_bytes=PAGE_BYTES)
    if https.ok or https.error in ("unresolved", "blocked_address", "dns_unknown"):
        return https, "https"
    http = ctx.http.fetch(f"http://{host}/", max_bytes=PAGE_BYTES)
    return (http, "http") if http.ok else (https, "https")


def same_page(data: dict, ref: dict) -> bool:
    """A host answers the way the wildcard does: the same body, or the same status and title."""
    if data.get("body_sha256") and data.get("body_sha256") == ref.get("body_sha256"):
        return True
    title = data.get("title", "")
    return bool(title) and data.get("status") == ref.get("status") and title == ref.get("title", "")  # no title, no basis


def page_evidence(source: str, host: str, fetch: Fetch, scheme: str, robots: Tri, robots_note: str,
                  wildcard_ref: dict | None = None, wildcard_host: bool = False) -> list[Evidence]:
    """wildcard_host: this host's DNS answer is the wildcard's answer. wildcard_ref: the page a
    made-up hostname returned (None if it could not be loaded)."""
    out: list[Evidence] = []
    data: dict = {
        "scheme": scheme, "error_class": classify(fetch), "error": fetch.error or "",
        "status": fetch.status, "final_url": fetch.final_url, "redirects": list(fetch.redirects),
        "address": fetch.address, "internal_addresses": list(fetch.internal_addresses),
        "robots": robots.value, "robots_note": robots_note,
    }
    if fetch.ok:
        data["headers"] = [[k, v] for k, v in fetch.headers]
        data["banners"] = extract_banners(fetch.headers)
        data["set_cookie_names"] = sorted({v.split("=", 1)[0].strip() for k, v in fetch.headers
                                            if k.lower() == "set-cookie"})
        data["content_type"] = fetch.header("content-type") or ""
        data["body_bytes"] = len(fetch.body)
        data["body_truncated"] = fetch.truncated
        data["body_sha256"] = hashlib.sha256(fetch.body).hexdigest()
        if is_html(fetch):
            sig = parse_html(fetch.body, fetch.final_url or fetch.url, charset_of(fetch))
            data.update({
                "title": sig.title, "og_site_name": sig.og_site_name, "generator": sig.generator,
                "has_password_form": sig.has_password_form, "form_actions": sig.form_actions,
                "script_srcs": sig.script_srcs, "iframe_srcs": sig.iframe_srcs, "icon_hrefs": sig.icon_hrefs,
                "custom_elements": sig.custom_elements, "links": sig.links,
                "certification_mentions": find_certifications(sig.text),
                "vendor_mentions": find_vendors(sig.text),
            })
    state = Tri.FOUND if fetch.ok else Tri.ABSENT if fetch.error == "unresolved" else Tri.UNKNOWN
    match = same_page(data, wildcard_ref) if wildcard_host and wildcard_ref and fetch.ok else None
    data["wildcard_host"] = wildcard_host
    data["wildcard_match"] = match
    if state is not Tri.FOUND:
        data["live"] = None
    elif wildcard_host:
        data["live"] = None if match is None else not match  # live only if the page differs from the wildcard's
    else:
        data["live"] = True
    out.append(make_evidence(source, "web_page", host, state, **data))
    if fetch.peer_cert_der:
        try:
            cert = parse_certificate(fetch.peer_cert_der, host)
            out.append(make_evidence(source, "certificate", host, Tri.FOUND, **cert))
        except Exception as exc:  # an unreadable certificate is not a finding
            out.append(make_evidence(source, "certificate", host, Tri.UNKNOWN, error=f"{type(exc).__name__}: {exc}"))
    elif scheme == "https" and fetch.error == "tls_failed":
        out.append(make_evidence(source, "certificate", host, Tri.UNKNOWN, error="tls handshake failed"))
    return out


class PageLoader:
    name = "page_loader"
    stage = 3

    def run(self, ctx: Context) -> SourceResult:
        hosts, skipped, capped = select_hosts(ctx)
        wildcard_hosts = {e.subject for e in ctx.evidence if e.kind == "host_dns" and e.data.get("matches_wildcard") is True}
        wildcard_ref, probe_evidence = self._wildcard_reference(ctx, hosts, wildcard_hosts)

        def load(host: str) -> tuple[list[Evidence], Tri]:
            robots, parser, note, allowed = robots_policy(ctx, host)
            if not allowed:
                reason = note or "robots.txt disallows the root page"
                ev = make_evidence(self.name, "web_page", host, Tri.UNKNOWN, robots=robots.value,
                                   error_class="robots_blocked", error="", robots_note=reason)
                return [ev], Tri.UNKNOWN
            fetch, scheme = load_root(ctx, host)
            evidence = page_evidence(self.name, host, fetch, scheme, robots, note, wildcard_ref,
                                     host in wildcard_hosts)
            if fetch.ok:
                ctx.captured.append(fetch)  # kept so ZAP can passive-scan it without a new request
            return evidence, evidence[0].state

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = list(pool.map(load, hosts))
        evidence = probe_evidence + [e for batch, _ in results for e in batch]
        states = [state for _, state in results]
        # A host with no address is a finding about DNS, not a failed page load.
        health = health_from([s for s in states if s is not Tri.ABSENT] or [Tri.FOUND]) if states else Health.OK
        notes = []
        if skipped:
            notes.append(f"{skipped} Microsoft-hosted service names not loaded")
        if capped:
            notes.append(f"loaded the first {MAX_PAGE_HOSTS} hosts")
        unknown = sum(s is Tri.UNKNOWN for s in states)
        if unknown:
            notes.append(f"{unknown} hosts not checked")
        if not hosts:
            notes.append("no live hosts to load")
        return SourceResult(health, evidence, "; ".join(notes))

    def _wildcard_reference(self, ctx: Context, hosts: list[str], wildcard_hosts: set[str]):
        """Load the root page of a made-up hostname so wildcard hosts can be compared with it."""
        wildcard = next((e for e in ctx.evidence if e.kind == "wildcard"), None)
        if wildcard is None or wildcard.state is not Tri.FOUND or not (wildcard_hosts & set(hosts)):
            return None, []
        probe = f"wc-{secrets.token_hex(6)}.{ctx.domain}"
        fetch, scheme = load_root(ctx, probe)
        page = page_evidence(self.name, probe, fetch, scheme, Tri.ABSENT, "")[0]
        ref = make_evidence(self.name, "wildcard_page", ctx.domain, page.state, **page.data)
        return (page.data if page.state is Tri.FOUND else None), [ref]
