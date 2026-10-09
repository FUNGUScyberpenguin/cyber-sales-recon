"""DNS discovery: records, mail policy, Microsoft 365 names, wildcard detection, CNAME chains."""
from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.resolver import DnsResolver
from reconbrief.sources.common import health_from, make_evidence, normalize_host

APEX_TYPES = ("A", "AAAA", "NS", "MX", "CAA", "TXT")
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "s1", "s2", "k1", "k2",
                  "mail", "dkim", "smtp", "mandrill", "mxvault", "zendesk1", "everlytickey1")
M365_NAMES = ("autodiscover", "lyncdiscover", "enterpriseregistration", "enterpriseenrollment", "msoid", "sip")
MICROSOFT_SUFFIXES = (".outlook.com", ".office365.com", ".office.com", ".microsoftonline.com",
                      ".microsoft.com", ".lync.com", ".manage.microsoft.com", ".msappproxy.net")
MAX_CHAIN = 8
MAX_HOSTS = 150


@dataclass
class Chain:
    name: str
    state: Tri
    chain: list[str] = field(default_factory=list)  # name, then each CNAME target
    addresses: tuple[str, ...] = ()
    dangling_target: str = ""  # a CNAME target that returned NXDOMAIN
    error: str = ""


def resolve_chain(resolver: DnsResolver, name: str) -> Chain:
    """Follow CNAMEs by hand, then read the addresses at the end. Any failed lookup is UNKNOWN."""
    chain = [name]
    current = name
    for _ in range(MAX_CHAIN):
        cname = resolver.query(current, "CNAME")
        if cname.state is Tri.UNKNOWN:
            return Chain(name, Tri.UNKNOWN, chain, error=cname.error)
        if cname.state is Tri.ABSENT:
            break
        target = cname.records[0].rstrip(".").lower()
        if target in chain:
            return Chain(name, Tri.FOUND, chain, error="cname loop")
        chain.append(target)
        current = target
    a, aaaa = resolver.query(current, "A"), resolver.query(current, "AAAA")
    addresses = tuple(a.records) + tuple(aaaa.records)
    if addresses:
        return Chain(name, Tri.FOUND, chain, addresses)
    if Tri.UNKNOWN in (a.state, aaaa.state):
        return Chain(name, Tri.UNKNOWN, chain, error=a.error or aaaa.error)
    if len(chain) > 1:
        dangling = current if a.error == "NXDOMAIN" else ""
        return Chain(name, Tri.FOUND, chain, dangling_target=dangling)
    return Chain(name, Tri.ABSENT, chain)


def points_to_microsoft(chain: list[str]) -> bool:
    return any(hop.endswith(MICROSOFT_SUFFIXES) for hop in chain[1:])


def chain_evidence(source: str, kind: str, host: str, result: Chain, **extra) -> list[Evidence]:
    out = [make_evidence(source, kind, host, result.state, chain=result.chain,
                         addresses=list(result.addresses), error=result.error, **extra)]
    if result.dangling_target:
        out.append(make_evidence(source, "dangling_cname", host, Tri.FOUND,
                                 chain=result.chain, target=result.dangling_target))
    return out


def _txt_with(records, prefix: str) -> list[str]:
    return [r for r in records if r.strip().lower().startswith(prefix)]


class DnsRecords:
    name = "dns_records"
    stage = 1

    def run(self, ctx: Context) -> SourceResult:
        domain, dns = ctx.domain, ctx.dns
        evidence: list[Evidence] = []
        raw = {}
        for rdtype in APEX_TYPES:
            raw[rdtype] = dns.query(domain, rdtype)
            r = raw[rdtype]
            evidence.append(make_evidence(self.name, "dns_record", f"{domain} {rdtype}", r.state,
                                          records=list(r.records), ttl=r.ttl, error=r.error))
        txt = raw["TXT"]
        evidence.append(self._policy("spf", domain, txt, "v=spf1"))
        dmarc = dns.query(f"_dmarc.{domain}", "TXT")
        evidence.append(self._policy("dmarc", f"_dmarc.{domain}", dmarc, "v=dmarc1"))
        mta = dns.query(f"_mta-sts.{domain}", "TXT")
        evidence.append(self._policy("mta_sts", f"_mta-sts.{domain}", mta, "v=stsv1"))
        tls_rpt = dns.query(f"_smtp._tls.{domain}", "TXT")
        evidence.append(self._policy("tls_rpt", f"_smtp._tls.{domain}", tls_rpt, "v=tlsrptv1"))
        evidence.append(self._dkim(ctx))
        for label in M365_NAMES:
            host = f"{label}.{domain}"
            result = resolve_chain(dns, host)
            evidence += chain_evidence(self.name, "m365_name", host, result,
                                       points_to_microsoft=points_to_microsoft(result.chain))
        evidence += chain_evidence(self.name, "cname_chain", f"www.{domain}", resolve_chain(dns, f"www.{domain}"))
        evidence.append(self._wildcard(ctx))
        core = [raw[t].state for t in ("A", "AAAA", "NS", "MX")]
        health = health_from(core)
        if health is Health.OK and any(e.state is Tri.UNKNOWN for e in evidence):
            health = Health.PARTIAL
        unknown = sum(e.state is Tri.UNKNOWN for e in evidence)
        detail = f"{unknown} lookups not checked" if unknown else ""
        return SourceResult(health, evidence, detail)

    def _policy(self, kind: str, subject: str, result, prefix: str) -> Evidence:
        if result.state is Tri.UNKNOWN:
            return make_evidence(self.name, kind, subject, Tri.UNKNOWN, error=result.error)
        matches = _txt_with(result.records, prefix)
        if matches:
            return make_evidence(self.name, kind, subject, Tri.FOUND, records=matches)
        return make_evidence(self.name, kind, subject, Tri.ABSENT)

    def _dkim(self, ctx: Context) -> Evidence:
        found, unknown, absent = [], [], []
        for selector in DKIM_SELECTORS:
            r = ctx.dns.query(f"{selector}._domainkey.{ctx.domain}", "TXT")
            if r.state is Tri.UNKNOWN:
                unknown.append(selector)
            elif r.state is Tri.FOUND and any("v=dkim1" in t.lower() or "p=" in t.lower() for t in r.records):
                found.append(selector)
            else:
                absent.append(selector)
        state = Tri.FOUND if found else Tri.UNKNOWN if unknown else Tri.ABSENT
        return make_evidence(self.name, "dkim", ctx.domain, state, selectors_found=found,
                             selectors_not_checked=unknown, selectors_checked=list(DKIM_SELECTORS))

    def _wildcard(self, ctx: Context) -> Evidence:
        probe = f"wc-{secrets.token_hex(6)}.{ctx.domain}"
        a, aaaa = ctx.dns.query(probe, "A"), ctx.dns.query(probe, "AAAA")
        addresses = sorted(set(a.records) | set(aaaa.records))
        if addresses:
            return make_evidence(self.name, "wildcard", ctx.domain, Tri.FOUND, addresses=addresses)
        if Tri.UNKNOWN in (a.state, aaaa.state):
            return make_evidence(self.name, "wildcard", ctx.domain, Tri.UNKNOWN, error=a.error or aaaa.error)
        return make_evidence(self.name, "wildcard", ctx.domain, Tri.ABSENT)


DISCOVERY_KINDS = ("ct_hostname", "archive_hostname", "urlscan_hostname")


def discovered_hosts(ctx: Context) -> dict[str, set[str]]:
    """Hostnames found by earlier sources, mapped to the sources that saw each one."""
    hosts: dict[str, set[str]] = {}
    for ev in ctx.evidence:
        if ev.kind in DISCOVERY_KINDS and ev.state is Tri.FOUND:
            host = normalize_host(ev.subject)
            if host:
                hosts.setdefault(host, set()).add(ev.source)
    return hosts


class HostResolution:
    """Resolve every discovered hostname: addresses, CNAME chain, dangling targets, wildcard match."""

    name = "host_resolution"
    stage = 2

    def run(self, ctx: Context) -> SourceResult:
        hosts = discovered_hosts(ctx)
        wildcard = next((e for e in ctx.evidence if e.kind == "wildcard"), None)
        wildcard_checked = wildcard is not None and wildcard.state is not Tri.UNKNOWN
        wildcard_addrs = set(wildcard.data["addresses"]) if wildcard and wildcard.state is Tri.FOUND else set()
        ordered = sorted(hosts, key=lambda h: (-len(hosts[h]), h))
        capped = len(ordered) > MAX_HOSTS
        ordered = ordered[:MAX_HOSTS]
        if not ordered:
            return SourceResult(Health.OK, [], "no discovered hosts to resolve")
        with ThreadPoolExecutor(max_workers=8) as pool:
            chains = list(pool.map(lambda h: resolve_chain(ctx.dns, h), ordered))
        evidence: list[Evidence] = []
        for host, result in zip(ordered, chains):
            if not wildcard_checked:
                same = None  # the wildcard probe failed, so "not a wildcard match" can't be claimed
            else:
                same = bool(result.addresses) and bool(wildcard_addrs) and set(result.addresses) <= wildcard_addrs
            evidence += chain_evidence(self.name, "host_dns", host, result,
                                       seen_by=sorted(hosts[host]), matches_wildcard=same)
        health = health_from([r.state for r in chains])
        notes = []
        if capped:
            notes.append(f"resolved the first {MAX_HOSTS} of {len(hosts)} hosts")
            health = Health.PARTIAL if health is Health.OK else health
        if not wildcard_checked:
            notes.append("wildcard not checked")
            health = Health.PARTIAL if health is Health.OK else health
        unknown = sum(r.state is Tri.UNKNOWN for r in chains)
        if unknown:
            notes.append(f"{unknown} hosts not checked")
        return SourceResult(health, evidence, "; ".join(notes))
