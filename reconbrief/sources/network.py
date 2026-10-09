"""Network context: Microsoft 365 tenant, RIPEstat prefix and ASN, and cloud provider IP ranges."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import quote

from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.base import make_evidence

REALM_URL = "https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain}&json=1"
OPENID_URL = "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
RIPESTAT_URL = "https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_URL = "https://www.gstatic.com/ipranges/cloud.json"
CLOUDFLARE_URLS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
MAX_IPS = 6
_GUID = re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/", re.I)


def apex_addresses(ctx: Context) -> list[str]:
    """Global A/AAAA addresses the DNS source found for the apex."""
    found: list[str] = []
    for e in ctx.evidence:
        if e.kind == "dns_record" and e.state is Tri.FOUND and e.data.get("name") == ctx.domain \
                and e.data.get("rdtype") in ("A", "AAAA"):
            for text in e.data.get("records", []):
                try:
                    ip = ipaddress.ip_address(text)
                except ValueError:
                    continue
                if ip.is_global and str(ip) not in found:
                    found.append(str(ip))
    return found[:MAX_IPS]


class M365Tenant:
    name = "m365"
    stage = 1

    def run(self, ctx: Context) -> SourceResult:
        r = ctx.api.get(REALM_URL.format(domain=quote(ctx.domain)))
        realm = r.json() if r.ok else None
        if not isinstance(realm, dict) or "NameSpaceType" not in realm:
            why = f"Microsoft realm lookup {r.why()}"
            ev = make_evidence(self.name, "m365_tenant", ctx.domain, Tri.UNKNOWN, error=why)
            return SourceResult(Health.FAILED, [ev], why)
        kind = str(realm["NameSpaceType"])
        if kind.lower() == "unknown":
            ev = make_evidence(self.name, "m365_tenant", ctx.domain, Tri.ABSENT, namespace_type=kind)
            return SourceResult(Health.OK, [ev])
        tenant_id = ""
        health, detail = Health.OK, ""
        t = ctx.api.get(OPENID_URL.format(domain=quote(ctx.domain)))
        cfg = t.json() if t.ok else None
        if isinstance(cfg, dict):
            m = _GUID.search(str(cfg.get("token_endpoint", "")))
            tenant_id = m.group(1).lower() if m else ""
        else:
            health, detail = Health.PARTIAL, f"tenant id lookup {t.why()}"
        ev = make_evidence(self.name, "m365_tenant", ctx.domain, Tri.FOUND, namespace_type=kind,
                           federated=kind.lower() == "federated",
                           brand=str(realm.get("FederationBrandName", "")),
                           auth_url=str(realm.get("AuthURL", "")), tenant_id=tenant_id)
        return SourceResult(health, [ev], detail)


class RipeStat:
    name = "ripestat"
    stage = 2

    def run(self, ctx: Context) -> SourceResult:
        ips = apex_addresses(ctx)
        if not ips:
            return SourceResult(Health.SKIPPED, [], "no apex addresses to look up")
        out: list[Evidence] = []
        failed = 0
        for ip in ips:
            r = ctx.api.get(RIPESTAT_URL.format(ip=quote(ip)))
            doc = r.json() if r.ok else None
            data = doc.get("data") if isinstance(doc, dict) else None
            if not isinstance(data, dict):
                failed += 1
                out.append(make_evidence(self.name, "ip_network", ip, Tri.UNKNOWN, ip=ip, error=r.why()))
                continue
            asns = [{"asn": a.get("asn"), "holder": str(a.get("holder", ""))} for a in data.get("asns") or []]
            state = Tri.FOUND if data.get("announced") and asns else Tri.ABSENT
            out.append(make_evidence(self.name, "ip_network", ip, state, ip=ip,
                                     prefix=str(data.get("resource", "")), asns=asns))
        health = Health.FAILED if failed == len(ips) else Health.PARTIAL if failed else Health.OK
        return SourceResult(health, out, f"{failed} of {len(ips)} lookups failed" if failed else "")


def _networks(texts) -> list:
    nets = []
    for text in texts:
        try:
            nets.append(ipaddress.ip_network(text.strip(), strict=False))
        except ValueError:
            continue
    return nets


class CloudRanges:
    """Which of the apex IPs sit inside AWS, Google Cloud, or Cloudflare published ranges."""

    name = "cloud_ranges"
    stage = 2

    def run(self, ctx: Context) -> SourceResult:
        ips = apex_addresses(ctx)
        if not ips:
            return SourceResult(Health.SKIPPED, [], "no apex addresses to look up")
        ranges: dict[str, list] = {}
        failed: list[str] = []
        for provider, loader in (("aws", self._aws), ("gcp", self._gcp), ("cloudflare", self._cloudflare)):
            nets = loader(ctx)
            if nets is None:
                failed.append(provider)
            else:
                ranges[provider] = nets
        out: list[Evidence] = []
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            hits = sorted(p for p, nets in ranges.items() if any(addr in n for n in nets if n.version == addr.version))
            if hits:
                state = Tri.FOUND
            elif failed:
                state = Tri.UNKNOWN  # a list we could not read might have held it
            else:
                state = Tri.ABSENT
            out.append(make_evidence(self.name, "ip_cloud", ip, state, ip=ip, providers=hits, lists_unread=failed))
        if len(failed) == 3:
            return SourceResult(Health.FAILED, out, "no provider range list could be read")
        return SourceResult(Health.PARTIAL if failed else Health.OK, out,
                            f"could not read: {', '.join(failed)}" if failed else "")

    def _aws(self, ctx: Context):
        r = ctx.api.get(AWS_URL)
        doc = r.json() if r.ok else None
        if not isinstance(doc, dict):
            return None
        return _networks([p.get("ip_prefix", "") for p in doc.get("prefixes", [])]
                         + [p.get("ipv6_prefix", "") for p in doc.get("ipv6_prefixes", [])]) or None

    def _gcp(self, ctx: Context):
        r = ctx.api.get(GCP_URL)
        doc = r.json() if r.ok else None
        if not isinstance(doc, dict):
            return None
        return _networks([p.get("ipv4Prefix") or p.get("ipv6Prefix") or "" for p in doc.get("prefixes", [])]) or None

    def _cloudflare(self, ctx: Context):
        texts: list[str] = []
        for url in CLOUDFLARE_URLS:
            r = ctx.api.get(url, {"Accept": "text/plain"})
            if not r.ok:
                return None
            texts.extend(r.body.decode("utf-8", "replace").split())
        return _networks(texts) or None  # an empty or unreadable list is not a list
