"""Certificate Transparency hostnames: crt.sh first, Cert Spotter if crt.sh fails."""
from __future__ import annotations

from urllib.parse import quote

from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.base import clean_hostname, make_evidence, under

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
CERTSPOTTER_URL = ("https://api.certspotter.com/v1/issuances?domain={domain}"
                   "&include_subdomains=true&expand=dns_names&expand=issuer")
CERTSPOTTER_MAX_PAGES = 10
MAX_HOSTS = 1500


class CertificateTransparency:
    name = "ct"
    stage = 1

    def run(self, ctx: Context) -> SourceResult:
        hosts, complete, provider, notes = self._crtsh(ctx)
        if hosts is None:
            crtsh_note = notes
            hosts, complete, provider, notes = self._certspotter(ctx)
            notes = f"crt.sh failed ({crtsh_note}); {notes}"
        if hosts is None:
            ev = make_evidence(self.name, "ct_lookup", ctx.domain, Tri.UNKNOWN, error=notes)
            return SourceResult(Health.FAILED, [ev], notes)
        out = self._evidence(ctx.domain, hosts, provider)
        if not hosts:
            out.append(make_evidence(self.name, "ct_lookup", ctx.domain, Tri.ABSENT, provider=provider))
        return SourceResult(Health.OK if complete else Health.PARTIAL, out, notes)

    def _evidence(self, domain: str, hosts: dict, provider: str) -> list[Evidence]:
        ranked = sorted(hosts.items(), key=lambda kv: kv[1]["last_seen"], reverse=True)
        kept = ranked[:MAX_HOSTS]
        out = [make_evidence(self.name, "hostname", host, Tri.FOUND, provider=provider, via="ct",
                             first_seen=info["first_seen"], last_seen=info["last_seen"],
                             issuers=sorted(info["issuers"]), wildcard_cert=info["wildcard"])
               for host, info in kept]
        out.append(make_evidence(self.name, "ct_summary", domain, Tri.FOUND, provider=provider,
                                 hostnames_total=len(hosts), hostnames_kept=len(kept)))
        return out

    @staticmethod
    def _add(hosts: dict, domain: str, raw: str, first: str, last: str, issuer: str) -> None:
        wildcard = raw.strip().startswith("*.")
        name = clean_hostname(raw)
        if name is None or not under(name, domain):
            return
        info = hosts.setdefault(name, {"first_seen": first, "last_seen": last, "issuers": set(), "wildcard": False})
        info["first_seen"] = min(info["first_seen"], first) if first else info["first_seen"]
        info["last_seen"] = max(info["last_seen"], last)
        info["wildcard"] = info["wildcard"] or wildcard
        if issuer:
            info["issuers"].add(issuer)

    def _crtsh(self, ctx: Context):
        r = ctx.api.get(CRTSH_URL.format(domain=quote(ctx.domain)))
        if not r.ok:
            return None, False, "crt.sh", f"{r.why()} after {r.attempts} tries"
        rows = r.json()
        if not isinstance(rows, list):
            return None, False, "crt.sh", "unreadable response"
        hosts: dict = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            first = str(row.get("not_before", ""))[:10]
            last = str(row.get("not_after", ""))[:10]
            issuer = str(row.get("issuer_name", ""))
            for raw in str(row.get("name_value", "")).splitlines():
                self._add(hosts, ctx.domain, raw, first, last, issuer)
        return hosts, True, "crt.sh", f"{len(rows)} certificates"

    def _certspotter(self, ctx: Context):
        hosts: dict = {}
        after = ""
        pages = 0
        complete = True
        for pages in range(1, CERTSPOTTER_MAX_PAGES + 1):
            url = CERTSPOTTER_URL.format(domain=quote(ctx.domain)) + (f"&after={after}" if after else "")
            r = ctx.api.get(url)
            rows = r.json() if r.ok else None
            if not isinstance(rows, list):
                if pages == 1:
                    return None, False, "certspotter", f"Cert Spotter {r.why()}"
                complete = False
                break
            for row in rows:
                if not isinstance(row, dict):
                    continue
                first = str(row.get("not_before", ""))[:10]
                last = str(row.get("not_after", ""))[:10]
                issuer = str((row.get("issuer") or {}).get("friendly_name", ""))
                for raw in row.get("dns_names") or []:
                    self._add(hosts, ctx.domain, str(raw), first, last, issuer)
            if len(rows) < 100 or not rows[-1].get("id"):
                break
            after = rows[-1]["id"]
        else:
            complete = False  # hit the page cap with more to read
        note = f"Cert Spotter, {pages} page{'s' if pages != 1 else ''}" + ("" if complete else ", not all read")
        return hosts, complete, "certspotter", note
