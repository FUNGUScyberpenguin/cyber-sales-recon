import json

import pytest

from reconbrief.models import Evidence, Health, Tri
from reconbrief.sources import vulns
from reconbrief.sources.vulns import Vulnerabilities, banner_targets, cpe_for
from tests.helpers import FakeHttp, make_ctx, recorded, response

KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def page_with(*banners, host="example.com"):
    return Evidence(f"wp:{host}", "page_loader", "web_page", host, Tri.FOUND, {"banners": list(banners)})


def banner(product, version, distro="", raw=None):
    return {"product": product, "version": version, "distro": distro, "raw": raw or f"{product}/{version}", "header": "server"}


def nvd_paged(url):
    page = "nvd_apache_page2.json" if "startIndex=2" in url else "nvd_apache_page1.json"
    return response(200, recorded(page))


@pytest.fixture(autouse=True)
def small_pages(monkeypatch):
    monkeypatch.setattr(vulns, "PAGE_SIZE", 2)


def run(routes, evidence, sleeps=None):
    sleeps = [] if sleeps is None else sleeps
    http = FakeHttp(routes)
    result = Vulnerabilities(sleep=sleeps.append).run(make_ctx(http=http, evidence=evidence))
    return result, {e.kind + ":" + e.subject: e for e in result.evidence}, http, sleeps


def test_every_nvd_page_is_read_and_kev_matches_are_flagged():
    result, found, http, _ = run([(KEV, recorded("kev_catalog_subset.json")), (NVD, nvd_paged)],
                                 [page_with(banner("Apache", "2.4.49"))])
    ev = found["vuln_lookup:Apache 2.4.49"]
    assert ev.state is Tri.FOUND and ev.data["total_results"] == 3 and ev.data["pages"] == 2 and ev.data["cve_count"] == 3
    assert ev.data["kev_ids"] == ["CVE-2021-41773", "CVE-2017-9798"] and ev.data["kev_checked"] is True
    assert [c["id"] for c in ev.data["cves"]] == ["CVE-2021-41773", "CVE-2017-9798", "CVE-2019-0211"]  # KEV first, then score
    assert ev.data["cves"][0]["score"] == 9.8 and ev.data["cves"][0]["severity"] == "CRITICAL"
    assert ev.data["cpe"] == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert found["kev_catalog:cisa-kev"].data["entries"] == 2 and result.health is Health.OK
    assert sum(u.startswith(NVD) for u in http.requested) == 2


def test_nvd_requests_are_paced():
    _, _, _, sleeps = run([(KEV, recorded("kev_catalog_subset.json")), (NVD, nvd_paged)], [page_with(banner("Apache", "2.4.49"))])
    assert sleeps == [vulns.NVD_PAUSE]  # the KEV download is not NVD; the second NVD page waits


def test_a_page_that_fails_leaves_the_product_unknown_with_no_cves():
    def second_fails(url):
        return response(503) if "startIndex=2" in url else response(200, recorded("nvd_apache_page1.json"))

    result, found, _, _ = run([(KEV, recorded("kev_catalog_subset.json")), (NVD, second_fails)],
                              [page_with(banner("Apache", "2.4.49"))])
    ev = found["vuln_lookup:Apache 2.4.49"]
    assert ev.state is Tri.UNKNOWN and "cves" not in ev.data and result.health is Health.PARTIAL


def test_throttled_nvd_is_retried_with_backoff():
    calls = []

    def flaky(url):
        calls.append(url)
        return response(403) if len(calls) < 3 else response(200, recorded("nvd_empty.json"))

    result, found, _, sleeps = run([(KEV, recorded("kev_catalog_subset.json")), (NVD, flaky)], [page_with(banner("nginx", "1.18.0"))])
    assert found["vuln_lookup:nginx 1.18.0"].state is Tri.ABSENT  # answered: no known vulnerabilities
    assert vulns.BACKOFF[0] in sleeps and vulns.BACKOFF[1] in sleeps


def test_kev_catalog_failure_means_kev_is_unknown_not_false():
    result, found, _, _ = run([(KEV, response(503)), (NVD, nvd_paged)], [page_with(banner("Apache", "2.4.49"))])
    assert found["kev_catalog:cisa-kev"].state is Tri.UNKNOWN
    ev = found["vuln_lookup:Apache 2.4.49"]
    assert ev.data["kev_checked"] is False and ev.data["kev_ids"] == [] and all(c["kev"] is None for c in ev.data["cves"])
    assert result.health is Health.PARTIAL


@pytest.mark.parametrize("distros, backports", [(["redhat"], True), (["debian"], True), (["ubuntu"], True), (["suse"], True),
                                                ([], False), (["other"], False)])
def test_distribution_is_recorded_so_backporting_can_cap_the_finding(distros, backports):
    b = banner("Apache", "2.4.6", distros[0] if distros else "")
    _, found, _, _ = run([(KEV, recorded("kev_catalog_subset.json")), (NVD, nvd_paged)], [page_with(b)])
    ev = found["vuln_lookup:Apache 2.4.6"]
    assert ev.data["distros"] == distros and ev.data["backports"] is backports


def test_same_banner_on_many_hosts_is_one_lookup_with_all_hosts():
    ev = [page_with(banner("Apache", "2.4.6", "redhat"), host="a.example.com"), page_with(banner("Apache", "2.4.6"), host="b.example.com")]
    targets = banner_targets(make_ctx(evidence=ev))
    assert list(targets) == [("Apache", "2.4.6")] and targets[("Apache", "2.4.6")]["hosts"] == ["a.example.com", "b.example.com"]
    assert targets[("Apache", "2.4.6")]["distros"] == {"redhat"}


def test_unmapped_products_and_failed_pages_are_not_looked_up():
    ev = [page_with(banner("cloudflare", "1"), banner("Express", "4.17.1")),
          Evidence("x", "page_loader", "web_page", "z.example.com", Tri.UNKNOWN, {"banners": [banner("nginx", "1.1.1")]})]
    result, found, http, _ = run([], ev)
    assert result.health is Health.SKIPPED and http.requested == []


def test_lookups_are_capped():
    ev = [page_with(*[banner("Apache", f"2.4.{i}") for i in range(12)])]
    result, found, _, _ = run([(KEV, recorded("kev_catalog_subset.json")), (NVD, response(200, recorded("nvd_empty.json")))], ev)
    assert sum(e.kind == "vuln_lookup" for e in result.evidence) == vulns.MAX_PRODUCTS
    assert result.health is Health.PARTIAL and "of 12" in result.detail


@pytest.mark.parametrize("product, version, cpe", [
    ("PHP", "5.4.16", "cpe:2.3:a:php:php:5.4.16:*:*:*:*:*:*:*"),
    ("OpenSSL", "1.0.2k-fips", "cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*"),
    ("Microsoft-IIS", "10.0", "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*"),
    ("Express", "4.1", None), ("nginx", "latest", None)])
def test_cpe_names(product, version, cpe):
    assert cpe_for(product, version) == cpe
