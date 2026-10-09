"""Hostnames from public web history: Wayback Machine and urlscan.io."""
from __future__ import annotations

from urllib.parse import quote, urlsplit

from reconbrief.models import Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.common import get_json, in_scope, make_evidence, normalize_host

WAYBACK_URL = ("https://web.archive.org/cdx/search/cdx?url=*.{d}&output=json&fl=original"
               "&collapse=urlkey&limit=5000")
URLSCAN_URL = "https://urlscan.io/api/v1/search/?q=domain:{d}&size=100"


def _hostname_evidence(source: str, kind: str, ctx: Context, counts: dict[str, int]):
    return [make_evidence(source, kind, host, Tri.FOUND, observations=n)
            for host, n in sorted(counts.items())]


class Wayback:
    name = "wayback"
    stage = 1

    def run(self, ctx: Context) -> SourceResult:
        result = get_json(ctx, WAYBACK_URL.format(d=quote(ctx.domain)))
        if result.state is Tri.UNKNOWN:
            return SourceResult(Health.FAILED, [], result.error)
        rows = result.data if result.state is Tri.FOUND and isinstance(result.data, list) else []
        counts: dict[str, int] = {}
        for row in rows[1:]:  # first row is the column header
            if not row:
                continue
            host = normalize_host(urlsplit(str(row[0])).hostname or "")
            if host and in_scope(host, ctx.domain):
                counts[host] = counts.get(host, 0) + 1
        evidence = _hostname_evidence(self.name, "archive_hostname", ctx, counts)
        if not evidence:
            evidence = [make_evidence(self.name, "archive_summary", ctx.domain, Tri.ABSENT)]
        return SourceResult(Health.OK, evidence)


class Urlscan:
    name = "urlscan"
    stage = 1

    def run(self, ctx: Context) -> SourceResult:
        result = get_json(ctx, URLSCAN_URL.format(d=quote(ctx.domain)))
        if result.state is Tri.UNKNOWN:
            return SourceResult(Health.FAILED, [], result.error)
        rows = result.data.get("results", []) if result.state is Tri.FOUND and isinstance(result.data, dict) else []
        counts: dict[str, int] = {}
        for row in rows:
            for field in ((row.get("page") or {}).get("domain"), (row.get("task") or {}).get("domain")):
                host = normalize_host(str(field or ""))
                if host and in_scope(host, ctx.domain):
                    counts[host] = counts.get(host, 0) + 1
        evidence = _hostname_evidence(self.name, "urlscan_hostname", ctx, counts)
        if not evidence:
            evidence = [make_evidence(self.name, "urlscan_summary", ctx.domain, Tri.ABSENT)]
        return SourceResult(Health.OK, evidence)
