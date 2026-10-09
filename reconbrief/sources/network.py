"""Network context: Microsoft 365 tenant, cloud provider IP ranges, RIPEstat ownership."""
from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import quote

from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.common import get_json, health_from, make_evidence

REALM_URL = "https://login.microsoftonline.com/getuserrealm.srf?login=user@{d}&json=1"
OPENID_URL = "https://login.microsoftonline.com/{d}/.well-known/openid-configuration"
GUID_RE = re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/", re.I)
AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_URL = "https://www.gstatic.com/ipranges/cloud.json"
CLOUDFLARE_URLS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
RIPESTAT_URL = "https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
MAX_IPS = 25


class M365Tenant:
    name = "m365_tenant"
    stage = 1

    def run(self, ctx: Context) -> SourceResult:
        realm = get_json(ctx, REALM_URL.format(d=quote(ctx.domain)))
        if realm.state is not Tri.FOUND or not isinstance(realm.data, dict):
            ev = make_evidence(self.name, "m365_tenant", ctx.domain, Tri.UNKNOWN,
                               error=realm.error or "no usable answer")
            return SourceResult(Health.FAILED, [ev], realm.error)
        namespace = str(realm.data.get("NameSpaceType", ""))
        if namespace not in ("Managed", "Federated"):
            return SourceResult(Health.OK, [make_evidence(self.name, "m365_tenant", ctx.domain, Tri.ABSENT,
                                                          namespace_type=namespace)])
        tenant_id, notes = "", ""
        fetch = ctx.http.fetch(OPENID_URL.format(d=quote(ctx.domain)))
        if fetch.ok and fetch.status == 200:
            try:
                match = GUID_RE.search(json.loads(fetch.body).get("token_endpoint", ""))
                tenant_id = match.group(1) if match else ""
            except ValueError:
                notes = "tenant id not readable"
        else:
            notes = "tenant id not checked"
        ev = make_evidence(self.name, "m365_tenant", ctx.domain, Tri.FOUND, namespace_type=namespace,
                           tenant_id=tenant_id, federation_brand=str(realm.data.get("FederationBrandName", "")))
        return SourceResult(Health.PARTIAL if notes else Health.OK, [ev], notes)


def public_ips(ctx: Context) -> list[str]:
    """Global addresses found by DNS sources, apex first, capped."""
    ips: list[str] = []
    for ev in ctx.evidence:
        if ev.state is not Tri.FOUND:
            continue
        if ev.kind == "dns_record" and ev.subject.split()[-1] in ("A", "AAAA"):
            found = ev.data.get("records", [])
        elif ev.kind in ("host_dns", "cname_chain"):
            found = ev.data.get("addresses", [])
        else:
            continue
        for text in found:
            try:
                ip = ipaddress.ip_address(text)
            except ValueError:
                continue
            if ip.is_global and str(ip) not in ips:
                ips.append(str(ip))
    return ips[:MAX_IPS]


def _networks(prefixes) -> list:
    out = []
    for text in prefixes:
        try:
            out.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
    return out


class CloudRanges:
    name = "cloud_ranges"
    stage = 3

    def run(self, ctx: Context) -> SourceResult:
        ips = public_ips(ctx)
        if not ips:
            return SourceResult(Health.SKIPPED, [], "no public addresses found")
        providers: dict[str, list[tuple]] = {}
        failed: list[str] = []
        aws = get_json(ctx, AWS_URL)
        if aws.state is Tri.FOUND and isinstance(aws.data, dict):
            rows = [(p["ip_prefix"], p.get("service", ""), p.get("region", "")) for p in aws.data.get("prefixes", [])]
            rows += [(p["ipv6_prefix"], p.get("service", ""), p.get("region", "")) for p in aws.data.get("ipv6_prefixes", [])]
            providers["aws"] = [(net, svc, reg) for (pre, svc, reg) in rows for net in _networks([pre])]
        else:
            failed.append("aws")
        gcp = get_json(ctx, GCP_URL)
        if gcp.state is Tri.FOUND and isinstance(gcp.data, dict):
            rows = [(p.get("ipv4Prefix") or p.get("ipv6Prefix", ""), p.get("service", ""), p.get("scope", ""))
                    for p in gcp.data.get("prefixes", [])]
            providers["gcp"] = [(net, svc, reg) for (pre, svc, reg) in rows for net in _networks([pre])]
        else:
            failed.append("gcp")
        cloudflare, cf_ok = [], True
        for url in CLOUDFLARE_URLS:
            fetch = ctx.http.fetch(url)
            if fetch.ok and fetch.status == 200:
                cloudflare += _networks(fetch.body.decode("utf-8", "replace").split())
            else:
                cf_ok = False
        if cf_ok:
            providers["cloudflare"] = [(net, "CDN", "") for net in cloudflare]
        else:
            failed.append("cloudflare")
        evidence: list[Evidence] = []
        for text in ips:
            ip = ipaddress.ip_address(text)
            hit = next(((prov, svc, reg) for prov, rows in providers.items() for (net, svc, reg) in rows
                        if ip.version == net.version and ip in net), None)
            if hit:
                evidence.append(make_evidence(self.name, "cloud_range", text, Tri.FOUND,
                                              provider=hit[0], service=hit[1], region=hit[2]))
            else:
                state = Tri.UNKNOWN if failed else Tri.ABSENT
                evidence.append(make_evidence(self.name, "cloud_range", text, state,
                                              not_checked=failed, checked=sorted(providers)))
        if len(failed) == 3:
            return SourceResult(Health.FAILED, evidence, "no provider range list could be loaded")
        detail = f"not checked: {', '.join(failed)}" if failed else ""
        return SourceResult(Health.PARTIAL if failed else Health.OK, evidence, detail)


class RipeStat:
    name = "ripestat"
    stage = 3

    def run(self, ctx: Context) -> SourceResult:
        ips = public_ips(ctx)
        if not ips:
            return SourceResult(Health.SKIPPED, [], "no public addresses found")
        evidence: list[Evidence] = []
        for ip in ips:
            r = get_json(ctx, RIPESTAT_URL.format(ip=quote(ip)))
            data = (r.data or {}).get("data", {}) if r.state is Tri.FOUND and isinstance(r.data, dict) else {}
            asns = data.get("asns") or []
            if r.state is Tri.UNKNOWN:
                evidence.append(make_evidence(self.name, "ip_network", ip, Tri.UNKNOWN, error=r.error))
            elif not asns:
                evidence.append(make_evidence(self.name, "ip_network", ip, Tri.ABSENT))
            else:
                evidence.append(make_evidence(self.name, "ip_network", ip, Tri.FOUND,
                                              prefix=data.get("block", {}).get("resource", "") if isinstance(data.get("block"), dict) else "",
                                              asn=asns[0].get("asn"), holder=asns[0].get("holder", "")))
        health = health_from([e.state for e in evidence])
        unknown = sum(e.state is Tri.UNKNOWN for e in evidence)
        return SourceResult(health, evidence, f"{unknown} addresses not checked" if unknown else "")
