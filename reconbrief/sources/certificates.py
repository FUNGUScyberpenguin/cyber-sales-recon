"""Certificate Transparency hostnames: crt.sh with backoff, then Cert Spotter if crt.sh fails."""
from __future__ import annotations

import time
from typing import Callable
from urllib.parse import quote

from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.common import (JsonResult, TRANSIENT, get_json, in_scope, make_evidence,
                                       normalize_host)

CRTSH_URL = "https://crt.sh/?q={q}&output=json"
CERTSPOTTER_URL = ("https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true"
                   "&expand=dns_names&expand=issuer")
BACKOFF_SECONDS = (2, 5, 12)
CERTSPOTTER_MAX_PAGES = 10


def _entry(host: str) -> dict:
    return {"names": set(), "wildcard": False, "issuers": set(), "not_before": "", "not_after": "", "certs": 0}


def _add(hosts: dict, domain: str, names, issuer: str, not_before: str, not_after: str) -> None:
    for raw in names:
        host = normalize_host(raw)
        if not host or not in_scope(host, domain):
            continue
        e = hosts.setdefault(host, _entry(host))
        e["certs"] += 1
        e["wildcard"] = e["wildcard"] or raw.strip().startswith("*.")
        if issuer:
            e["issuers"].add(issuer)
        e["not_before"] = min(filter(None, [e["not_before"], not_before]), default="")
        e["not_after"] = max(filter(None, [e["not_after"], not_after]), default="")


class CertificateTransparency:
    name = "certificate_transparency"
    stage = 1

    def __init__(self, sleep: Callable[[float], None] = time.sleep) -> None:
        self.sleep = sleep

    def run(self, ctx: Context) -> SourceResult:
        hosts: dict = {}
        crt = self._crtsh(ctx, hosts)
        provider, notes, health = "crt.sh", [], Health.OK
        if crt.state is Tri.UNKNOWN:
            notes.append(f"crt.sh failed ({crt.error})")
            hosts.clear()
            spotter, pages_ok, complete = self._certspotter(ctx, hosts)
            provider = "certspotter"
            if spotter.state is Tri.UNKNOWN and not hosts:
                return SourceResult(Health.FAILED, [], "; ".join(notes + [f"Cert Spotter failed ({spotter.error})"]))
            notes.append("used Cert Spotter instead")
            if not complete:
                health = Health.PARTIAL
                notes.append(f"Cert Spotter returned {pages_ok} pages, not all certificates")
        evidence = self._evidence(ctx.domain, hosts, provider)
        if not hosts:
            evidence.append(make_evidence(self.name, "ct_summary", ctx.domain, Tri.ABSENT, provider=provider))
        else:
            evidence.append(make_evidence(self.name, "ct_summary", ctx.domain, Tri.FOUND,
                                          provider=provider, host_count=len(hosts)))
        return SourceResult(health, evidence, "; ".join(notes))

    def _crtsh(self, ctx: Context, hosts: dict) -> JsonResult:
        url = CRTSH_URL.format(q=quote(f"%.{ctx.domain}"))
        result = JsonResult(Tri.UNKNOWN, error="not tried")
        for attempt in range(len(BACKOFF_SECONDS) + 1):
            result = get_json(ctx, url)
            retry = result.state is Tri.UNKNOWN and (result.status in TRANSIENT or result.status is None)
            if not retry or result.truncated:
                break
            if attempt < len(BACKOFF_SECONDS):
                self.sleep(BACKOFF_SECONDS[attempt])
        if result.state is not Tri.FOUND:
            return result if result.state is Tri.UNKNOWN else JsonResult(Tri.FOUND, [])
        if not isinstance(result.data, list):
            return JsonResult(Tri.UNKNOWN, error="unexpected crt.sh response")
        for row in result.data:
            names = str(row.get("name_value", "")).splitlines() + [str(row.get("common_name", ""))]
            _add(hosts, ctx.domain, names, str(row.get("issuer_name", "")),
                 str(row.get("not_before", "")), str(row.get("not_after", "")))
        return result

    def _certspotter(self, ctx: Context, hosts: dict):
        url = CERTSPOTTER_URL.format(d=quote(ctx.domain))
        last = JsonResult(Tri.UNKNOWN, error="not tried")
        after, pages = "", 0
        while pages < CERTSPOTTER_MAX_PAGES:
            last = get_json(ctx, url + (f"&after={after}" if after else ""))
            if last.state is not Tri.FOUND or not isinstance(last.data, list):
                if last.state is Tri.FOUND:
                    last = JsonResult(Tri.UNKNOWN, error="unexpected Cert Spotter response")
                break
            pages += 1
            if not last.data:
                return last, pages, True
            for row in last.data:
                issuer = (row.get("issuer") or {}).get("name", "") if isinstance(row.get("issuer"), dict) else ""
                _add(hosts, ctx.domain, row.get("dns_names") or [], issuer,
                     str(row.get("not_before", "")), str(row.get("not_after", "")))
            after = str(last.data[-1].get("id", ""))
            if not after:
                break
        else:
            return last, pages, False  # hit the page cap with more left
        if last.state is Tri.UNKNOWN:
            return last, pages, False
        return last, pages, True

    def _evidence(self, domain: str, hosts: dict, provider: str) -> list[Evidence]:
        return [
            make_evidence(self.name, "ct_hostname", host, Tri.FOUND, provider=provider,
                          wildcard_cert=e["wildcard"], issuers=sorted(e["issuers"]),
                          not_before=e["not_before"], not_after=e["not_after"], cert_count=e["certs"])
            for host, e in sorted(hosts.items())
        ]
