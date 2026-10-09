"""Hostnames seen by the Wayback Machine and urlscan.io."""
from __future__ import annotations

from urllib.parse import quote, urlsplit

from reconbrief.models import Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.base import clean_hostname, make_evidence, under

WAYBACK_URL = ("https://web.archive.org/cdx/search/cdx?url={domain}&matchType=domain"
               "&fl=original&collapse=urlkey&output=json&limit={limit}")
URLSCAN_URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size={size}"
MAX_HOSTS = 500
WAYBACK_LIMIT = 10000
URLSCAN_SIZE = 100


class WaybackHostnames:
    name = "wayback"
    stage = 1

    def run(self, ctx: Context) -> SourceResult:
        r = ctx.api.get(WAYBACK_URL.format(domain=quote(ctx.domain), limit=WAYBACK_LIMIT))
        rows = r.json() if r.ok else None
        if r.ok and r.body.strip() == b"":
            rows = []  # the CDX server answers an empty body when it has nothing
        if not isinstance(rows, list):
            why = f"Wayback {r.why()}"
            ev = make_evidence(self.name, "archive_lookup", ctx.domain, Tri.UNKNOWN, error=why)
            return SourceResult(Health.FAILED, [ev], why)
        counts: dict[str, int] = {}
        for row in rows[1:]:  # first row is the header
            if not row:
                continue
            host = clean_hostname(urlsplit(str(row[0])).hostname or "")
            if host and under(host, ctx.domain):
                counts[host] = counts.get(host, 0) + 1
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_HOSTS]
        out = [make_evidence(self.name, "hostname", h, Tri.FOUND, via="wayback", archived_urls=n) for h, n in top]
        if not out:
            out.append(make_evidence(self.name, "archive_lookup", ctx.domain, Tri.ABSENT))
        cut = len(rows) - 1 >= WAYBACK_LIMIT
        return SourceResult(Health.PARTIAL if cut else Health.OK, out,
                            f"{len(counts)} hostnames" + ("; result hit the row limit" if cut else ""))


class UrlscanHostnames:
    name = "urlscan"
    stage = 1

    def run(self, ctx: Context) -> SourceResult:
        r = ctx.api.get(URLSCAN_URL.format(domain=quote(ctx.domain), size=URLSCAN_SIZE))
        doc = r.json() if r.ok else None
        if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
            why = f"urlscan {r.why()}"
            ev = make_evidence(self.name, "archive_lookup", ctx.domain, Tri.UNKNOWN, error=why)
            return SourceResult(Health.FAILED, [ev], why)
        hosts: dict[str, dict] = {}
        for item in doc["results"]:
            page = (item or {}).get("page") or {}
            host = clean_hostname(str(page.get("domain", "")))
            if not host or not under(host, ctx.domain):
                continue
            info = hosts.setdefault(host, {"ips": set(), "last_seen": ""})
            if page.get("ip"):
                info["ips"].add(str(page["ip"]))
            info["last_seen"] = max(info["last_seen"], str((item.get("task") or {}).get("time", ""))[:10])
        out = [make_evidence(self.name, "hostname", h, Tri.FOUND, via="urlscan",
                             ips=sorted(i["ips"]), last_seen=i["last_seen"]) for h, i in sorted(hosts.items())]
        if not out:
            out.append(make_evidence(self.name, "archive_lookup", ctx.domain, Tri.ABSENT))
        cut = len(doc["results"]) >= URLSCAN_SIZE
        return SourceResult(Health.PARTIAL if cut else Health.OK, out,
                            f"{len(hosts)} hostnames" + ("; result hit the size limit" if cut else ""))
