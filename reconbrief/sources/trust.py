"""Trust and security posture: the trust center and security.txt.

A trust center counts as absent only when the check really ran: the homepage loaded, it had links
to read, and every candidate answered. A DNS-only run, or a homepage that failed to load, leaves
the trust center unknown.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

from reconbrief.http import USER_AGENT
from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.common import in_scope, make_evidence, normalize_host
from reconbrief.sources.htmlsignals import parse_html
from reconbrief.sources.pages import PAGE_BYTES, ROBOTS_BYTES, charset_of, is_html
from reconbrief.sources.patterns import find_certifications, find_vendors, platform_vendor

MAX_CANDIDATES = 5
TRUST_PATH = re.compile(r"/(?:[^/]*[-_])?(trust|security|compliance)(?:[-_][^/]*)?(?:/|$)", re.I)
TRUST_TEXT = re.compile(r"\b(trust\s+(?:center|centre|portal|page|&\s*security|and\s+security)|"
                        r"security(?:\s+(?:&|and)\s+compliance)?|compliance|security\s+center)\b", re.I)
TRUST_TITLE = re.compile(r"\b(trust|security|compliance)\b", re.I)
TRUST_HOST_LABELS = ("trust", "security")
DISCOVERY_KINDS = ("ct_hostname", "archive_hostname", "urlscan_hostname", "host_dns")
SECURITY_TXT_FIELDS = ("contact", "expires", "policy", "encryption", "acknowledgments", "canonical",
                       "preferred-languages", "hiring")


def homepage(ctx: Context) -> Evidence | None:
    """The loaded HTML root page: the domain itself, else www."""
    for host in (ctx.domain, f"www.{ctx.domain}"):
        for e in ctx.evidence:
            if e.kind == "web_page" and e.subject == host and e.state is Tri.FOUND and "title" in e.data \
                    and 200 <= (e.data.get("status") or 0) < 300:  # an error page is not the homepage
                return e
    return None


def candidate_urls(ctx: Context, home: Evidence | None) -> list[tuple[str, str]]:
    """(url, how it was found), best first, at most MAX_CANDIDATES."""
    return ranked_candidates(ctx, home)[:MAX_CANDIDATES]


def ranked_candidates(ctx: Context, home: Evidence | None) -> list[tuple[str, str]]:
    ranked: list[tuple[int, str, str]] = []
    seen_hosts: set[str] = set()
    for e in ctx.evidence:
        if e.kind in DISCOVERY_KINDS and e.state is Tri.FOUND:
            host = normalize_host(e.subject)
            if host and host not in seen_hosts and in_scope(host, ctx.domain) \
                    and host.split(".")[0] in TRUST_HOST_LABELS and host != ctx.domain:
                seen_hosts.add(host)
                ranked.append((1, f"https://{host}/", "discovered_host"))
    for link in (home.data.get("links", []) if home else []):
        parts = urlsplit(link["href"])
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https") or not host:
            continue
        on_platform, _ = platform_vendor(host)
        if not (in_scope(host, ctx.domain) or on_platform):
            continue
        by_path, by_text = bool(TRUST_PATH.search(parts.path)), bool(TRUST_TEXT.search(link["text"]))
        by_host = host.split(".")[0] in TRUST_HOST_LABELS
        if not (by_path or by_text or by_host or on_platform and "trust" in parts.path.lower()):
            continue
        rank = 0 if on_platform else 1 if by_host else 2 if by_path else 3
        url = f"https://{host}{parts.path or '/'}"
        ranked.append((rank, url, "homepage_link"))
    out, seen = [], set()
    for _, url, how in sorted(ranked, key=lambda r: (r[0], r[1])):
        key = url.rstrip("/")
        if key not in seen:
            seen.add(key)
            out.append((url, how))
    return out


class _Robots:
    """robots.txt per host, read once. A server error on robots.txt means stay out (RFC 9309)."""

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.cache: dict[str, RobotFileParser | None | bool] = {}

    def allows(self, url: str) -> bool:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if host not in self.cache:
            f = self.ctx.http.fetch(f"https://{host}/robots.txt", max_bytes=ROBOTS_BYTES)
            if f.ok and f.status == 200:
                p = RobotFileParser()
                p.parse(f.body.decode("utf-8", "replace").splitlines())
                self.cache[host] = p
            else:
                self.cache[host] = False if f.ok and f.status >= 500 else None
        policy = self.cache[host]
        if policy is False:
            return False
        return True if policy is None else policy.can_fetch(USER_AGENT, parts.path or "/")


def check_trust_page(ctx: Context, url: str, how: str, home: Evidence | None) -> Evidence:
    host = urlsplit(url).hostname or ""
    base = {"url": url, "found_via": how}
    fetch = ctx.http.fetch(url, max_bytes=PAGE_BYTES)
    if not fetch.ok:
        return make_evidence("trust", "trust_page", url, Tri.UNKNOWN, error=fetch.error, **base)
    final_host = urlsplit(fetch.final_url).hostname or host
    if fetch.status in (404, 410):
        return make_evidence("trust", "trust_page", url, Tri.ABSENT, status=fetch.status, **base)
    if fetch.status != 200 or not is_html(fetch):
        return make_evidence("trust", "trust_page", url, Tri.UNKNOWN, status=fetch.status,
                             error=f"HTTP {fetch.status}", **base)
    sig = parse_html(fetch.body, fetch.final_url, charset_of(fetch))
    digest = hashlib.sha256(fetch.body).hexdigest()
    soft_404 = bool(home) and (digest == home.data.get("body_sha256")
                               or (sig.title and sig.title == home.data.get("title")))
    on_platform, platform = platform_vendor(final_host)
    vendors = find_vendors(sig.text)
    certs = find_certifications(sig.text)
    trusty_host = final_host.split(".")[0] in TRUST_HOST_LABELS
    looks_like_trust = on_platform or trusty_host or bool(certs) or bool(TRUST_TITLE.search(sig.title))
    state = Tri.ABSENT if soft_404 or not looks_like_trust else Tri.FOUND
    return make_evidence("trust", "trust_page", url, state, status=fetch.status, final_url=fetch.final_url,
                         title=sig.title, soft_404=soft_404, platform=platform if on_platform else "",
                         vendors=vendors, certifications=certs, **base)


def parse_security_txt(text: str) -> dict:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines()[:200]:
        if line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key in SECURITY_TXT_FIELDS and value.strip():
            fields.setdefault(key, []).append(value.strip())
    expires = fields.get("expires", [""])[0]
    expired = None
    try:
        expired = datetime.fromisoformat(expires.replace("Z", "+00:00")) < datetime.now(timezone.utc)
    except ValueError:
        pass
    return {"fields": fields, "expires": expires, "expired": expired}


def check_security_txt(ctx: Context, robots: _Robots, home: Evidence | None) -> Evidence:
    url = f"https://{ctx.domain}/.well-known/security.txt"
    if not robots.allows(url):
        return make_evidence("trust", "security_txt", ctx.domain, Tri.UNKNOWN, url=url, error="robots.txt disallows")
    fetch = ctx.http.fetch(url, max_bytes=100_000)
    if not fetch.ok:
        return make_evidence("trust", "security_txt", ctx.domain, Tri.UNKNOWN, url=url, error=fetch.error)
    if fetch.status in (404, 410):
        return make_evidence("trust", "security_txt", ctx.domain, Tri.ABSENT, url=url, status=fetch.status)
    if fetch.status != 200:  # 403, 429, 5xx: a block or an outage is not an answer
        return make_evidence("trust", "security_txt", ctx.domain, Tri.UNKNOWN, url=url, status=fetch.status,
                             error=f"HTTP {fetch.status}")
    text = fetch.body.decode("utf-8", "replace")
    parsed = parse_security_txt(text)
    homepage_copy = bool(home) and hashlib.sha256(fetch.body).hexdigest() == home.data.get("body_sha256")
    if is_html(fetch) or homepage_copy or "contact" not in parsed["fields"]:
        return make_evidence("trust", "security_txt", ctx.domain, Tri.ABSENT, url=url, status=200,
                             soft_404=True)
    return make_evidence("trust", "security_txt", ctx.domain, Tri.FOUND, url=url, status=200, **parsed)


class TrustPosture:
    name = "trust"
    stage = 4

    def run(self, ctx: Context) -> SourceResult:
        home = homepage(ctx)
        if home is None:  # no loaded homepage (a DNS-only run, or the load failed): nothing to check from
            ev = make_evidence(self.name, "trust_center", ctx.domain, Tri.UNKNOWN, reason="homepage not loaded")
            return SourceResult(Health.SKIPPED, [ev], "homepage not loaded, so trust pages were not checked")
        robots = _Robots(ctx)
        evidence: list[Evidence] = []
        ranked = ranked_candidates(ctx, home)
        candidates = ranked[:MAX_CANDIDATES]
        pages: list[Evidence] = []
        for url, how in candidates:
            if not robots.allows(url):
                pages.append(make_evidence(self.name, "trust_page", url, Tri.UNKNOWN, url=url, found_via=how,
                                           error="robots.txt disallows"))
            else:
                pages.append(check_trust_page(ctx, url, how, home))
        evidence += pages
        evidence.append(check_security_txt(ctx, robots, home))
        evidence.append(self._summary(ctx, home, candidates, pages, len(ranked) - len(candidates)))
        unknown = sum(e.state is Tri.UNKNOWN for e in evidence)
        health = Health.OK if not unknown else Health.PARTIAL
        return SourceResult(health, evidence, f"{unknown} lookups not checked" if unknown else "")

    def _summary(self, ctx, home: Evidence, candidates, pages, unchecked: int) -> Evidence:
        found = [p for p in pages if p.state is Tri.FOUND]
        if found:
            best = found[0].data
            return make_evidence(self.name, "trust_center", ctx.domain, Tri.FOUND, url=best.get("final_url") or best["url"],
                                 platform=best.get("platform", ""),
                                 vendors=sorted({v for p in found for v in p.data.get("vendors", [])}),
                                 certifications=sorted({c for p in found for c in p.data.get("certifications", [])}),
                                 found_via=best["found_via"])
        if not home.data.get("links") and not candidates:
            return make_evidence(self.name, "trust_center", ctx.domain, Tri.UNKNOWN,
                                 reason="homepage had no links to read")
        if any(p.state is Tri.UNKNOWN for p in pages) or unchecked:
            return make_evidence(self.name, "trust_center", ctx.domain, Tri.UNKNOWN,
                                 reason="a candidate page was not checked" if not unchecked else
                                 f"{unchecked} more candidate pages were not checked")
        return make_evidence(self.name, "trust_center", ctx.domain, Tri.ABSENT,
                             candidates_checked=[c[0] for c in candidates], homepage_links=len(home.data.get("links", [])))
