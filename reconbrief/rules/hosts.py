"""Rules about hostnames: non-production names, internal names in certificates, stale hosts,
internal addresses in public DNS, and the size of the attack surface."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

from reconbrief.models import Finding, Tier, Tri
from reconbrief.rules.common import Index, all_non_global, label_tokens, make_finding, parse_time, shown
from reconbrief.sources.common import in_scope

STRONG_NONPROD = {"dev", "staging", "stg", "uat", "qa", "test", "preprod"}
WEAK_NONPROD = {"demo", "beta", "old", "lab", "pilot", "canary"}
NONPROD_LENSES = ("external-pentest", "web-app-api", "continuous-exposure-management")
INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".intranet", ".home", ".localdomain", ".private")
STALE_AFTER = timedelta(days=365)


def _resolving(ix: Index) -> dict[str, "object"]:
    """host -> host_dns evidence, for hosts that have DNS addresses and count as real hosts.

    A host that answers the way the wildcard does is left out unless its page differs. If the wildcard
    check itself failed (matches_wildcard is None), the host is left out too: that is not a known answer."""
    out = {}
    for host, e in ix.host_dns.items():
        if e.state is not Tri.FOUND or not e.data.get("addresses") or host in ix.m365_microsoft:
            continue
        wildcard = e.data.get("matches_wildcard")
        if wildcard is False or (wildcard is True and ix.page_ok(host)):
            out[host] = e
    return out


def _weak_page_signal(ix: Index, host: str, word: str) -> bool:
    page = ix.pages.get(host)
    if not ix.page_ok(host) or page is None:
        return False
    d = page.data
    in_title = word in re.split(r"[^a-z0-9]+", (d.get("title") or "").lower())
    return in_title or bool(d.get("has_password_form")) or d.get("status") in (401, 403)


def non_production_hosts(ix: Index) -> list[Finding]:
    strong: dict[str, list] = {}
    weak: dict[str, list] = {}
    for host, dns in _resolving(ix).items():
        if not in_scope(host, ix.domain) or host == ix.domain:
            continue
        tokens = label_tokens(host, ix.domain)
        if tokens & STRONG_NONPROD:
            strong[host] = [dns]
        elif (words := tokens & WEAK_NONPROD) and any(_weak_page_signal(ix, host, w) for w in words):
            weak[host] = [dns, ix.pages[host]]
    out = []
    for key, group, tier, title, why in (
        ("strong", strong, Tier.ASK, "Non-production hostnames are public",
         "named like test or staging systems"),
        ("weak", weak, Tier.BACKGROUND, "Hostnames that look like demo or pilot systems",
         "named like demo or pilot systems, and the page behind each one shows a sign of it"),
    ):
        if group:
            evidence = [e for items in group.values() for e in items]
            out.append(make_finding("non_production_hosts", key, title,
                                    f"{len(group)} public host(s) {why}: {shown(sorted(group))}.",
                                    tier, evidence, NONPROD_LENSES))
    return out


def _internal_name(name: str) -> bool:
    name = name.lower().strip().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not name:
        return False
    try:
        return not ipaddress.ip_address(name).is_global
    except ValueError:
        pass
    return "." not in name or name.endswith(INTERNAL_SUFFIXES)


def internal_names_in_certificates(ix: Index) -> list[Finding]:
    hits, evidence = {}, []
    for cert in ix.kind("certificate", Tri.FOUND):
        if cert.subject in ix.m365_microsoft or not ix.page_ok(cert.subject):
            continue
        names = [n for n in cert.data.get("san", []) if _internal_name(n)]
        if names:
            evidence.append(cert)
            for n in names:
                hits.setdefault(n, cert.subject)
    if not hits:
        return []
    return [make_finding("internal_names_in_certificates", "san",
                         "Internal names appear in public certificates",
                         f"{len(hits)} certificate name(s) look internal: {shown(sorted(hits))}.",
                         Tier.BACKGROUND, evidence, ("red-team", "external-pentest"))]


def stale_hosts(ix: Index) -> list[Finding]:
    now = datetime.now(timezone.utc)
    stale, evidence = {}, []
    for host, dns in _resolving(ix).items():
        ct = next((e for e in ix.kind("ct_hostname", Tri.FOUND) if e.subject == host), None)
        newest = parse_time(ct.data.get("not_after", "")) if ct else None
        if newest is None or now - newest < STALE_AFTER or ix.page_ok(host):
            continue
        stale[host] = (now - newest).days
        evidence += [dns, ct]
    if not stale:
        return []
    detail = "; ".join(f"{h} (last certificate ended {d} days ago)" for h, d in sorted(stale.items())[:5])
    more = f" and {len(stale) - 5} more" if len(stale) > 5 else ""
    return [make_finding("stale_hosts", "dns_without_certificate",
                         "DNS still points at hosts whose certificates ended long ago",
                         f"{len(stale)} host(s) still resolve in DNS, and their newest public certificate "
                         f"expired over a year ago: {detail}{more}.",
                         Tier.BACKGROUND, evidence, ("continuous-exposure-management", "external-pentest"))]


def internal_addresses(ix: Index) -> list[Finding]:
    hits, evidence = [], []
    for host, e in sorted(ix.host_dns.items()):
        if e.state is Tri.FOUND and host not in ix.m365_microsoft and all_non_global(e.data.get("addresses", [])):
            hits.append(host)
            evidence.append(e)
    for rtype in ("A", "AAAA"):
        e = ix.one("dns_record", f"{ix.domain} {rtype}")
        if e is not None and e.state is Tri.FOUND and all_non_global(e.data.get("records", [])):
            hits.append(f"{ix.domain} ({rtype})")
            evidence.append(e)
    if not hits:
        return []
    return [make_finding("internal_addresses", "public_dns", "Internal addresses published in public DNS",
                         f"{len(hits)} name(s) resolve only to private or reserved addresses: {shown(hits)}.",
                         Tier.BACKGROUND, evidence, ("red-team", "continuous-exposure-management"))]


def attack_surface(ix: Index) -> list[Finding]:
    discovered = {e.subject for k in ("ct_hostname", "archive_hostname", "urlscan_hostname") for e in ix.kind(k, Tri.FOUND)
                  if in_scope(e.subject, ix.domain)}
    resolving = _resolving(ix)
    live = ix.live_pages()
    if not discovered and not live:
        return []
    providers = sorted({e.data.get("provider", "") for e in ix.kind("cloud_range", Tri.FOUND)} - {""})
    asns = {e.data.get("asn") for e in ix.kind("ip_network", Tri.FOUND) if e.data.get("asn")}
    parts = [f"{len(discovered)} hostnames found in public records", f"{len(resolving)} resolve in DNS",
             f"{len(live)} answered with a web page"]
    if providers:
        parts.append("hosted on " + shown(providers))
    if asns:
        parts.append(f"across {len(asns)} network(s)")
    evidence = list(resolving.values()) + live + ix.kind("cloud_range", Tri.FOUND) + ix.kind("ip_network", Tri.FOUND)
    evidence += ix.kind("ct_summary") if not evidence else []
    if not evidence:
        evidence = [e for k in ("ct_hostname", "archive_hostname", "urlscan_hostname") for e in ix.kind(k, Tri.FOUND)][:50]
    tier = Tier.ASK if len(live) >= 20 else Tier.BACKGROUND  # a sizing signal: many live hosts means a wide surface
    return [make_finding("attack_surface", "summary", "Size of the public footprint", "; ".join(parts) + ".",
                         tier, evidence, ("continuous-exposure-management", "external-pentest"))]
