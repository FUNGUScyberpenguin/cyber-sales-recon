"""Before a run: can this network reach every host the engine needs?

A 403, a 407, or a response with proxy headers counts as blocked. A host that does not answer at
all counts as unreachable. A run needs every core host.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from reconbrief.http import HttpClient

CORE_HOSTS = {
    "rdap.org": "https://rdap.org/",
    "crt.sh": "https://crt.sh/",
    "api.certspotter.com": "https://api.certspotter.com/",
    "web.archive.org": "https://web.archive.org/",
    "urlscan.io": "https://urlscan.io/",
    "login.microsoftonline.com": "https://login.microsoftonline.com/",
    "stat.ripe.net": "https://stat.ripe.net/",
    "ip-ranges.amazonaws.com": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "www.gstatic.com": "https://www.gstatic.com/ipranges/cloud.json",
    "www.cloudflare.com": "https://www.cloudflare.com/ips-v4",
    "www.cisa.gov": "https://www.cisa.gov/",
    "services.nvd.nist.gov": "https://services.nvd.nist.gov/",
    "www.wikidata.org": "https://www.wikidata.org/",
    "api.gleif.org": "https://api.gleif.org/",
    "www.sec.gov": "https://www.sec.gov/",
    "data.sec.gov": "https://data.sec.gov/",
}
PROXY_HEADERS = {"proxy-authenticate", "proxy-connection", "x-squid-error", "x-bluecoat-via", "x-proxy-id",
                 "x-zscaler-ip", "x-iinfo-proxy", "x-forcepoint"}
PROXY_VIA_WORDS = ("squid", "proxy", "bluecoat", "zscaler", "forcepoint", "websense")
PROBE_BYTES = 2_000


@dataclass
class PreflightResult:
    blocked: list[str] = field(default_factory=list)
    unreachable: list[str] = field(default_factory=list)
    checked: int = 0

    @property
    def ok(self) -> bool:
        return not self.blocked and not self.unreachable

    def to_dict(self) -> dict:
        return {"ok": self.ok, "checked": self.checked, "blocked": self.blocked, "unreachable": self.unreachable}

    def message(self) -> str:
        if self.ok:
            return f"All {self.checked} required hosts are reachable."
        parts = []
        if self.blocked:
            parts.append("blocked: " + ", ".join(self.blocked))
        if self.unreachable:
            parts.append("not reachable: " + ", ".join(self.unreachable))
        return "The network stops this run from reaching required hosts (" + "; ".join(parts) + ")."


def looks_blocked(status: int | None, headers: list[tuple[str, str]]) -> bool:
    if status in (403, 407):
        return True
    for key, value in headers:
        k = key.lower()
        if k in PROXY_HEADERS or (k == "via" and any(w in value.lower() for w in PROXY_VIA_WORDS)):
            return True
    return False


def run_preflight(http: HttpClient, hosts: dict[str, str] | None = None) -> PreflightResult:
    hosts = CORE_HOSTS if hosts is None else hosts
    result = PreflightResult(checked=len(hosts))
    with ThreadPoolExecutor(max_workers=8) as pool:
        fetches = list(pool.map(lambda url: http.fetch(url, max_bytes=PROBE_BYTES), hosts.values()))
    for host, fetch in zip(hosts, fetches):
        if not fetch.ok:
            result.unreachable.append(host)
        elif looks_blocked(fetch.status, fetch.headers):
            result.blocked.append(host)
    return result
