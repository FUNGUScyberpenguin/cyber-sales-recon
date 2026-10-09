"""DNS records for the domain, then CNAME chains and dangling CNAMEs for discovered hosts."""
from __future__ import annotations

import secrets

from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.resolver import DnsResolver
from reconbrief.sources.base import make_evidence, under

APEX_TYPES = ("A", "AAAA", "NS", "MX", "CAA", "TXT")
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
                  "dkim", "mail", "mandrill", "smtp", "mxvault", "everlytickey1")
M365_NAMES = ("autodiscover", "lyncdiscover", "enterpriseregistration", "enterpriseenrollment", "msoid", "sip")
MICROSOFT_SUFFIXES = (".microsoft.com", ".office.com", ".office365.com", ".outlook.com", ".microsoftonline.com",
                      ".lync.com", ".msidentity.com", ".manage.microsoft.com", ".windows.net", ".azure.com")
COMMON_HOSTS = ("www", "mail", "webmail")
MAX_CNAME_HOPS = 8
MAX_HOST_CHECKS = 150


def is_microsoft(target: str) -> bool:
    t = "." + target.lower().rstrip(".")
    return any(t.endswith(s) for s in MICROSOFT_SUFFIXES)


def cname_chain(dns: DnsResolver, name: str) -> tuple[Tri, list[str], str]:
    """Follow CNAMEs from name. Returns (state, chain, error). ABSENT means name has no CNAME."""
    chain: list[str] = []
    current = name
    for _ in range(MAX_CNAME_HOPS):
        r = dns.query(current, "CNAME")
        if r.state is Tri.UNKNOWN:
            return Tri.UNKNOWN, chain, r.error
        if r.state is Tri.ABSENT:
            break
        target = r.records[0].rstrip(".").lower()
        if target in chain or target == name:
            return Tri.FOUND, chain + [target], "loop"
        chain.append(target)
        current = target
    return (Tri.FOUND if chain else Tri.ABSENT), chain, ""


def dangling(dns: DnsResolver, target: str) -> tuple[Tri, str]:
    """FOUND if the CNAME target does not exist (NXDOMAIN on A and AAAA), ABSENT if it resolves."""
    states = [dns.query(target, t) for t in ("A", "AAAA")]
    if any(r.state is Tri.FOUND for r in states):
        return Tri.ABSENT, ""
    if any(r.state is Tri.UNKNOWN for r in states):
        return Tri.UNKNOWN, next(r.error for r in states if r.state is Tri.UNKNOWN)
    if all(r.error == "NXDOMAIN" for r in states):
        return Tri.FOUND, "NXDOMAIN"
    return Tri.ABSENT, "name exists with no address"  # exists, just has no A/AAAA


class DnsRecords:
    name = "dns"
    stage = 1

    def run(self, ctx: Context) -> SourceResult:
        d, dns = ctx.domain, ctx.dns
        out: list[Evidence] = []
        unknown = 0

        def record(kind: str, name: str, rdtype: str, **extra) -> object:
            nonlocal unknown
            r = dns.query(name, rdtype)
            if r.state is Tri.UNKNOWN:
                unknown += 1
            out.append(make_evidence(self.name, kind, f"{name}/{rdtype}", r.state,
                                     name=name, rdtype=rdtype, records=list(r.records),
                                     error=r.error, ttl=r.ttl, dnssec_ad=r.flags.get("ad", False), **extra))
            return r

        for rdtype in APEX_TYPES:
            r = record("dns_record", d, rdtype)
            if rdtype == "TXT":
                spf = [t for t in r.records if t.lower().startswith("v=spf1")]
                state = r.state if r.state is Tri.UNKNOWN else (Tri.FOUND if spf else Tri.ABSENT)
                out.append(make_evidence(self.name, "spf", d, state, records=spf, count=len(spf)))
        record("dmarc", f"_dmarc.{d}", "TXT")
        record("mta_sts", f"_mta-sts.{d}", "TXT")
        record("tls_rpt", f"_smtp._tls.{d}", "TXT")
        for sel in DKIM_SELECTORS:
            record("dkim_selector", f"{sel}._domainkey.{d}", "TXT", selector=sel)

        self._wildcard(ctx, out)

        names = [f"{n}.{d}" for n in (*M365_NAMES, *COMMON_HOSTS)]
        for host in names:
            state, chain, error = cname_chain(dns, host)
            if state is Tri.UNKNOWN:
                unknown += 1
            out.append(make_evidence(
                self.name, "cname_chain", host, state, host=host, chain=chain, error=error,
                microsoft=bool(chain) and is_microsoft(chain[-1]), m365_name=host.split(".")[0] in M365_NAMES))
            if chain:
                dstate, detail = dangling(dns, chain[-1])
                if dstate is Tri.UNKNOWN:
                    unknown += 1
                out.append(make_evidence(self.name, "dangling_cname", host, dstate, host=host,
                                         target=chain[-1], detail=detail,
                                         microsoft=is_microsoft(chain[-1])))

        failed_all = unknown and all(e.state is Tri.UNKNOWN for e in out)
        health = Health.FAILED if failed_all else Health.PARTIAL if unknown else Health.OK
        return SourceResult(health, out, f"{unknown} of {len(out)} lookups failed" if unknown else "")

    def _wildcard(self, ctx: Context, out: list[Evidence]) -> None:
        label = "reconbrief-" + secrets.token_hex(6)
        probe = f"{label}.{ctx.domain}"
        answers: list[str] = []
        states = []
        for rdtype in ("A", "AAAA", "CNAME"):
            r = ctx.dns.query(probe, rdtype)
            states.append(r.state)
            answers.extend(r.records)
        if Tri.FOUND in states:
            state = Tri.FOUND
        elif Tri.UNKNOWN in states:
            state = Tri.UNKNOWN
        else:
            state = Tri.ABSENT
        out.append(make_evidence(self.name, "wildcard", ctx.domain, state, answers=sorted(answers)))


class HostDns:
    """CNAME chains and dangling CNAMEs for hostnames other sources discovered."""

    name = "dns_hosts"
    stage = 2

    def run(self, ctx: Context) -> SourceResult:
        seen: dict[str, None] = {}
        for e in ctx.evidence:
            if e.kind == "hostname" and under(e.subject, ctx.domain) and e.subject != ctx.domain:
                seen.setdefault(e.subject)
        done = {e.subject for e in ctx.evidence if e.kind == "cname_chain"}
        hosts = [h for h in seen if h not in done][:MAX_HOST_CHECKS]
        out: list[Evidence] = []
        unknown = 0
        for host in hosts:
            state, chain, error = cname_chain(ctx.dns, host)
            if state is Tri.UNKNOWN:
                unknown += 1
            out.append(make_evidence(self.name, "cname_chain", host, state, host=host, chain=chain,
                                     error=error, microsoft=bool(chain) and is_microsoft(chain[-1]),
                                     m365_name=host.split(".")[0] in M365_NAMES))
            if chain:
                dstate, detail = dangling(ctx.dns, chain[-1])
                if dstate is Tri.UNKNOWN:
                    unknown += 1
                out.append(make_evidence(self.name, "dangling_cname", host, dstate, host=host,
                                         target=chain[-1], detail=detail, microsoft=is_microsoft(chain[-1])))
        capped = len(seen) - len(set(seen) & done) > MAX_HOST_CHECKS
        note = f"checked {len(hosts)} hosts" + ("; capped" if capped else "")
        if unknown:
            note += f"; {unknown} lookups failed"
        return SourceResult(Health.PARTIAL if unknown else Health.OK, out, note)
