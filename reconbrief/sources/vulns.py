"""Known-vulnerability context for the software versions that server banners announced.

CISA KEV is the list of vulnerabilities attackers are using now. NVD lists the vulnerabilities that
affect a product and version; every page of an NVD answer is read. A banner version is a claim by the
server, so the evidence records which Linux distribution the banner named: Red Hat, Debian, Ubuntu,
and SUSE backport fixes without changing the version number.
"""
from __future__ import annotations

import re
import time
from typing import Callable
from urllib.parse import quote

from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.common import TRANSIENT, JsonResult, get_json, make_evidence
from reconbrief.sources.patterns import BACKPORTING_DISTROS

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = ("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}&isVulnerable"
           "&resultsPerPage={size}&startIndex={start}")
PAGE_SIZE = 2000
NVD_PAUSE = 6.5  # NVD asks unkeyed clients for at most 5 requests per 30 seconds
BACKOFF = (6, 15, 30)
MAX_PRODUCTS = 8
KEEP_CVES = 25
# banner product (lowercase) -> (CPE vendor, CPE product)
CPE_PRODUCTS = {
    "apache": ("apache", "http_server"), "nginx": ("f5", "nginx"), "php": ("php", "php"),
    "microsoft-iis": ("microsoft", "internet_information_services"), "openssl": ("openssl", "openssl"),
    "lighttpd": ("lighttpd", "lighttpd"), "jetty": ("eclipse", "jetty"), "openssh": ("openbsd", "openssh"),
}
_VERSION = re.compile(r"^\d+(?:\.\d+)*[a-z]?")


def cpe_for(product: str, version: str) -> str | None:
    pair = CPE_PRODUCTS.get(product.lower())
    m = _VERSION.match(version)
    return f"cpe:2.3:a:{pair[0]}:{pair[1]}:{m.group(0)}:*:*:*:*:*:*:*" if pair and m else None


def banner_targets(ctx: Context) -> dict[tuple[str, str], dict]:
    """Distinct (product, version) pairs from page banners, with the hosts and distributions seen."""
    targets: dict[tuple[str, str], dict] = {}
    for e in ctx.evidence:
        if e.kind != "web_page" or e.state is not Tri.FOUND:
            continue
        for b in e.data.get("banners", []):
            cpe = cpe_for(b["product"], b["version"])
            if not cpe:
                continue
            t = targets.setdefault((b["product"], b["version"]), {"cpe": cpe, "hosts": [], "distros": set(), "raw": set()})
            if e.subject not in t["hosts"]:
                t["hosts"].append(e.subject)
            if b.get("distro"):
                t["distros"].add(b["distro"])
            t["raw"].add(b["raw"])
    return targets


def _score(cve: dict) -> tuple[float | None, str]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            return data.get("baseScore"), str(data.get("baseSeverity") or metrics[key][0].get("baseSeverity") or "")
    return None, ""


class Vulnerabilities:
    name = "vulnerabilities"
    stage = 4

    def __init__(self, sleep: Callable[[float], None] = time.sleep) -> None:
        self.sleep = sleep
        self._requests = 0

    def run(self, ctx: Context) -> SourceResult:
        targets = banner_targets(ctx)
        if not targets:
            return SourceResult(Health.SKIPPED, [], "no versioned software banners to look up")
        ordered = sorted(targets, key=lambda k: (-len(targets[k]["hosts"]), k))
        capped = len(ordered) > MAX_PRODUCTS
        evidence: list[Evidence] = []
        kev_ev, kev_ids = self._kev(ctx)
        evidence.append(kev_ev)
        states = [kev_ev.state]
        for key in ordered[:MAX_PRODUCTS]:
            ev = self._lookup(ctx, key, targets[key], kev_ids)
            evidence.append(ev)
            states.append(ev.state)
        health = Health.FAILED if all(s is Tri.UNKNOWN for s in states) else \
            Health.PARTIAL if Tri.UNKNOWN in states or capped else Health.OK
        notes = []
        if capped:
            notes.append(f"looked up {MAX_PRODUCTS} of {len(ordered)} software versions")
        if Tri.UNKNOWN in states:
            notes.append(f"{states.count(Tri.UNKNOWN)} lookups not checked")
        return SourceResult(health, evidence, "; ".join(notes))

    def _kev(self, ctx: Context) -> tuple[Evidence, set[str] | None]:
        result = get_json(ctx, KEV_URL)
        vulns = result.data.get("vulnerabilities") if result.state is Tri.FOUND and isinstance(result.data, dict) else None
        if not isinstance(vulns, list):
            err = result.error or "unreadable KEV catalog"
            return make_evidence(self.name, "kev_catalog", "cisa-kev", Tri.UNKNOWN, error=err), None
        ids = {v["cveID"] for v in vulns if isinstance(v, dict) and v.get("cveID")}
        return make_evidence(self.name, "kev_catalog", "cisa-kev", Tri.FOUND, entries=len(ids),
                             catalog_version=result.data.get("catalogVersion", ""),
                             date_released=result.data.get("dateReleased", "")), ids

    def _page(self, ctx: Context, url: str) -> JsonResult:
        result = JsonResult(Tri.UNKNOWN, error="not requested")
        for attempt in range(len(BACKOFF) + 1):
            if self._requests:
                self.sleep(NVD_PAUSE)
            self._requests += 1
            result = get_json(ctx, url)
            retry = result.state is Tri.UNKNOWN and (result.status in TRANSIENT or result.status == 403)
            if not retry or attempt == len(BACKOFF):
                break
            self.sleep(BACKOFF[attempt])
        return result

    def _lookup(self, ctx: Context, key: tuple[str, str], target: dict, kev_ids: set[str] | None) -> Evidence:
        product, version = key
        base = {"product": product, "version": version, "cpe": target["cpe"], "hosts": target["hosts"],
                "banners": sorted(target["raw"]), "distros": sorted(target["distros"]),
                "backports": bool(target["distros"] & BACKPORTING_DISTROS)}
        cves: list[dict] = []
        start, total, pages = 0, None, 0
        while total is None or start < total:
            page = self._page(ctx, NVD_URL.format(cpe=quote(target["cpe"], safe=":*"), size=PAGE_SIZE, start=start))
            if page.state is not Tri.FOUND or not isinstance(page.data, dict):
                # Half an answer is not an answer: no CVE list from a partly read result.
                return make_evidence(self.name, "vuln_lookup", f"{product} {version}", Tri.UNKNOWN,
                                     error=page.error or f"NVD page {pages + 1} not readable", **base)
            pages += 1
            total = int(page.data.get("totalResults", 0))
            for item in page.data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                score, severity = _score(cve)
                desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                cves.append({"id": cve.get("id", ""), "score": score, "severity": severity,
                             "published": cve.get("published", ""), "summary": desc[:240],
                             "kev": None if kev_ids is None else cve.get("id", "") in kev_ids})
            got = len(page.data.get("vulnerabilities", []))
            if got == 0:
                break
            start += got
        complete = len(cves) >= (total or 0)
        if not complete:
            return make_evidence(self.name, "vuln_lookup", f"{product} {version}", Tri.UNKNOWN,
                                 error=f"read {len(cves)} of {total} results", **base)
        cves.sort(key=lambda c: (c["kev"] is True, c["score"] or 0), reverse=True)
        kev_hits = [c["id"] for c in cves if c["kev"]]
        return make_evidence(self.name, "vuln_lookup", f"{product} {version}",
                             Tri.FOUND if cves else Tri.ABSENT, total_results=total, pages=pages,
                             cve_count=len(cves), cves=cves[:KEEP_CVES], kev_ids=kev_hits,
                             kev_checked=kev_ids is not None, **base)
