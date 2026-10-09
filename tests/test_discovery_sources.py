import json

from discovery_helpers import fixture, make_ctx, ok
from reconbrief.models import Evidence, Health, Tri
from reconbrief.sources.archive import UrlscanHostnames, WaybackHostnames
from reconbrief.sources.ct import CertificateTransparency
from reconbrief.sources.network import CloudRanges, M365Tenant, RipeStat
from reconbrief.sources.rdap import Rdap, normalize_status

BOOT = ("data.iana.org/rdap/dns.json", ok("rdap_bootstrap.json"))
RDAP_URL = "rdap.verisign.com/com/v1/domain/example.com"


def hosts(result):
    return {e.subject: e for e in result.evidence if e.kind == "hostname"}


# ---- Certificate Transparency

def test_crtsh_hostnames_are_cleaned_and_scoped_to_the_domain():
    ctx, _ = make_ctx(routes=[("crt.sh", ok("crtsh_example.json"))])
    r = CertificateTransparency().run(ctx)
    h = hosts(r)
    assert set(h) == {"example.com", "www.example.com", "staging.example.com", "vpn.example.com", "upper.example.com"}
    assert h["example.com"].data["wildcard_cert"] is True
    assert h["example.com"].data["provider"] == "crt.sh"
    assert r.health is Health.OK


def test_crtsh_502_falls_back_to_certspotter():
    ctx, api = make_ctx(routes=[
        ("crt.sh", (502, b"<html>Bad Gateway</html>")),
        ("certspotter", ok("certspotter_example_p1.json")),
    ])
    r = CertificateTransparency().run(ctx)
    assert set(hosts(r)) == {"example.com", "www.example.com", "dev.example.com"}
    assert all(e.data["provider"] == "certspotter" for e in hosts(r).values())
    assert r.health is Health.OK and "crt.sh failed" in r.detail
    assert any("crt.sh" in c for c in api.calls) and any("certspotter" in c for c in api.calls)


def test_crtsh_unreadable_body_also_falls_back():
    ctx, _ = make_ctx(routes=[("crt.sh", (200, b"<html>rate limited</html>")),
                              ("certspotter", ok("certspotter_example_p1.json"))])
    assert "dev.example.com" in hosts(CertificateTransparency().run(ctx))


def test_both_ct_sources_failing_is_unknown_not_empty():
    ctx, _ = make_ctx(routes=[("crt.sh", (502, b"")), ("certspotter", (429, b""))])
    r = CertificateTransparency().run(ctx)
    assert r.health is Health.FAILED
    assert [e.state for e in r.evidence] == [Tri.UNKNOWN]


def test_certspotter_stops_at_the_page_cap_and_says_partial():
    page = json.dumps([{"id": str(i), "dns_names": [f"h{i}.example.com"], "not_before": "", "not_after": ""}
                       for i in range(100)]).encode()
    ctx, api = make_ctx(routes=[("crt.sh", (502, b"")), ("certspotter", (200, page))])
    r = CertificateTransparency().run(ctx)
    assert r.health is Health.PARTIAL
    assert sum("certspotter" in c for c in api.calls) == 10


# ---- RDAP

def test_locked_com_has_transfer_lock_true():
    ctx, _ = make_ctx(routes=[BOOT, (RDAP_URL, ok("rdap_example_com_locked.json"))])
    r = Rdap().run(ctx)
    d = r.evidence[0]
    assert d.state is Tri.FOUND and d.data["transfer_lock"] is True
    assert d.data["delete_lock"] and d.data["update_lock"]
    assert d.data["expires"] == "2027-08-13T04:00:00Z" and d.data["dnssec_signed"] is True
    assert d.data["statuses"] == ["clientdeleteprohibited", "clienttransferprohibited", "clientupdateprohibited"]
    assert d.data["registrar"].startswith("RESERVED")
    assert d.data["registrant_org"] == ""  # redacted values are not recorded as a name


def test_unlocked_domain_has_transfer_lock_false_and_keeps_open_registrant():
    ctx, _ = make_ctx(routes=[BOOT, (RDAP_URL, ok("rdap_example_com_unlocked.json"))])
    d = Rdap().run(ctx).evidence[0]
    assert d.data["transfer_lock"] is False and d.data["registrant_org"] == "Example Holdings LLC"


def test_status_strings_are_normalized():
    for s in ("client transfer prohibited", "clientTransferProhibited", "client_transfer-prohibited"):
        assert normalize_status(s) == "clienttransferprohibited"


def test_rdap_404_means_not_registered_but_500_means_unknown():
    ctx, _ = make_ctx(routes=[BOOT, (RDAP_URL, (404, b"{}"))])
    assert Rdap().run(ctx).evidence[0].state is Tri.ABSENT
    ctx, _ = make_ctx(routes=[BOOT, (RDAP_URL, (500, b""))])
    r = Rdap().run(ctx)
    assert r.evidence[0].state is Tri.UNKNOWN and r.health is Health.FAILED


def test_rdap_bootstrap_failure_is_unknown():
    ctx, _ = make_ctx(routes=[("data.iana.org", (503, b""))])
    assert Rdap().run(ctx).evidence[0].state is Tri.UNKNOWN


def test_rdap_on_a_subdomain_asks_for_the_parent():
    ctx, api = make_ctx(domain="app.example.com",
                        routes=[BOOT, ("domain/app.example.com", (404, b"{}")),
                                (RDAP_URL, ok("rdap_example_com_locked.json"))])
    d = Rdap().run(ctx).evidence[0]
    assert d.state is Tri.FOUND and d.data["queried"] == "example.com"


# ---- Wayback and urlscan

def test_wayback_hostnames():
    ctx, _ = make_ctx(routes=[("web.archive.org", ok("wayback_example.json"))])
    r = WaybackHostnames().run(ctx)
    h = hosts(r)
    assert set(h) == {"example.com", "www.example.com", "old.example.com"}  # lookalike domain dropped
    assert h["www.example.com"].data["archived_urls"] == 2


def test_wayback_empty_body_is_absent_and_error_is_unknown():
    ctx, _ = make_ctx(routes=[("web.archive.org", (200, b""))])
    assert WaybackHostnames().run(ctx).evidence[0].state is Tri.ABSENT
    ctx, _ = make_ctx(routes=[("web.archive.org", (503, b""))])
    r = WaybackHostnames().run(ctx)
    assert r.evidence[0].state is Tri.UNKNOWN and r.health is Health.FAILED


def test_urlscan_hostnames_and_ips():
    ctx, _ = make_ctx(routes=[("urlscan.io", ok("urlscan_example.json"))])
    h = hosts(UrlscanHostnames().run(ctx))
    assert set(h) == {"app.example.com"}
    assert h["app.example.com"].data["ips"] == ["203.0.113.10", "203.0.113.11"]


def test_urlscan_rate_limited_is_unknown():
    ctx, _ = make_ctx(routes=[("urlscan.io", (429, b""))])
    r = UrlscanHostnames().run(ctx)
    assert r.evidence[0].state is Tri.UNKNOWN and r.health is Health.FAILED


# ---- Microsoft 365

REALM = "getuserrealm.srf"
OPENID = "well-known/openid-configuration"


def test_m365_managed_tenant_with_id():
    ctx, _ = make_ctx(routes=[(REALM, ok("m365_realm_managed.json")), (OPENID, ok("m365_openid.json"))])
    e = M365Tenant().run(ctx).evidence[0]
    assert e.state is Tri.FOUND and e.data["namespace_type"] == "Managed"
    assert e.data["tenant_id"] == "72f988bf-86f1-41af-91ab-2d7cd011db47" and e.data["brand"] == "Example Corp"


def test_m365_unknown_namespace_is_absent_and_failure_is_unknown():
    ctx, _ = make_ctx(routes=[(REALM, ok("m365_realm_unknown.json"))])
    assert M365Tenant().run(ctx).evidence[0].state is Tri.ABSENT
    ctx, _ = make_ctx(routes=[(REALM, (500, b""))])
    r = M365Tenant().run(ctx)
    assert r.evidence[0].state is Tri.UNKNOWN and r.health is Health.FAILED


def test_m365_tenant_id_failure_is_partial_not_absent():
    ctx, _ = make_ctx(routes=[(REALM, ok("m365_realm_managed.json")), (OPENID, (500, b""))])
    r = M365Tenant().run(ctx)
    assert r.evidence[0].state is Tri.FOUND and r.health is Health.PARTIAL


# ---- RIPEstat and cloud ranges

def with_apex(ctx, ip="3.5.140.10"):
    ctx.evidence.append(Evidence("E-a", "dns", "dns_record", "example.com/A", Tri.FOUND,
                                 {"name": "example.com", "rdtype": "A", "records": [ip, "10.0.0.5"]}))


CLOUD_ROUTES = [("ip-ranges.amazonaws.com", ok("aws_ranges.json")), ("gstatic.com", ok("gcp_ranges.json")),
                ("cloudflare.com/ips-v4", ok("cloudflare_v4.txt")), ("cloudflare.com/ips-v6", ok("cloudflare_v6.txt"))]


def test_ripestat_prefix_and_asn_for_global_addresses_only():
    ctx, api = make_ctx(routes=[("stat.ripe.net", ok("ripestat_prefix.json"))])
    with_apex(ctx)
    r = RipeStat().run(ctx)
    e = r.evidence[0]
    assert len(r.evidence) == 1 and "10.0.0.5" not in " ".join(api.calls)
    assert e.state is Tri.FOUND and e.data["asns"][0]["holder"] == "AMAZON-02"


def test_ripestat_failure_is_unknown():
    ctx, _ = make_ctx(routes=[("stat.ripe.net", (500, b""))])
    with_apex(ctx)
    r = RipeStat().run(ctx)
    assert r.evidence[0].state is Tri.UNKNOWN and r.health is Health.FAILED


def test_sources_that_need_addresses_skip_without_them():
    ctx, _ = make_ctx()
    assert RipeStat().run(ctx).health is Health.SKIPPED
    assert CloudRanges().run(ctx).health is Health.SKIPPED


def test_cloud_range_hit_and_miss():
    ctx, _ = make_ctx(routes=CLOUD_ROUTES)
    with_apex(ctx)
    assert CloudRanges().run(ctx).evidence[0].data["providers"] == ["aws"]
    ctx, _ = make_ctx(routes=CLOUD_ROUTES)
    with_apex(ctx, "93.184.216.34")
    e = CloudRanges().run(ctx).evidence[0]
    assert e.state is Tri.ABSENT


def test_unreadable_range_list_makes_a_miss_unknown():
    ctx, _ = make_ctx(routes=[CLOUD_ROUTES[0], ("gstatic.com", (500, b"")), *CLOUD_ROUTES[2:]])
    with_apex(ctx, "93.184.216.34")
    r = CloudRanges().run(ctx)
    assert r.evidence[0].state is Tri.UNKNOWN and r.health is Health.PARTIAL


def test_cloud_list_with_an_unusable_body_is_unknown_not_absent():
    for bad in (b"{}", b"", b"<html>maintenance</html>"):
        ctx, _ = make_ctx(routes=[("ip-ranges.amazonaws.com", (200, bad)), *CLOUD_ROUTES[1:]])
        with_apex(ctx, "93.184.216.34")
        r = CloudRanges().run(ctx)
        assert r.evidence[0].state is Tri.UNKNOWN and r.health is Health.PARTIAL, bad


def test_archive_results_cut_off_by_the_limit_are_partial():
    import json as _json
    rows = [["original"]] + [[f"https://h{i}.example.com/"] for i in range(10000)]
    ctx, _ = make_ctx(routes=[("web.archive.org", (200, _json.dumps(rows).encode()))])
    assert WaybackHostnames().run(ctx).health is Health.PARTIAL
    results = [{"page": {"domain": f"h{i}.example.com"}, "task": {}} for i in range(100)]
    ctx, _ = make_ctx(routes=[("urlscan.io", (200, _json.dumps({"results": results}).encode()))])
    assert UrlscanHostnames().run(ctx).health is Health.PARTIAL
