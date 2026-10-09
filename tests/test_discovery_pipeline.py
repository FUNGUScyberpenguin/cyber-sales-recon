from discovery_helpers import make_ctx, ok
from reconbrief.models import Health, Tri
from reconbrief.pipeline import Pipeline
from reconbrief.sources import discovery_sources

ZONE = {
    ("example.com", "A"): ["3.5.140.10"],
    ("shop.example.com", "CNAME"): ["gone.nowhere-host.net."],
    ("staging.example.com", "A"): ["3.5.140.11"],
}
ROUTES = [
    ("crt.sh", ok("crtsh_example.json")),
    ("data.iana.org", ok("rdap_bootstrap.json")),
    ("rdap.verisign.com", ok("rdap_example_com_locked.json")),
    ("web.archive.org", ok("wayback_example.json")),
    ("urlscan.io", ok("urlscan_example.json")),
    ("getuserrealm", ok("m365_realm_managed.json")),
    ("openid-configuration", ok("m365_openid.json")),
    ("stat.ripe.net", ok("ripestat_prefix.json")),
    ("ip-ranges.amazonaws.com", ok("aws_ranges.json")),
    ("gstatic.com", ok("gcp_ranges.json")),
    ("cloudflare.com/ips-v4", ok("cloudflare_v4.txt")),
    ("cloudflare.com/ips-v6", ok("cloudflare_v6.txt")),
]


def test_all_discovery_sources_run_together_and_later_stages_use_earlier_evidence():
    ctx, api = make_ctx(ZONE, ROUTES)
    result = Pipeline(discovery_sources()).run(ctx)
    status = {h.source: h.status for h in result.health}
    assert set(status) == {"dns", "ct", "rdap", "wayback", "urlscan", "m365", "dns_hosts", "ripestat", "cloud_ranges"}
    assert all(s is Health.OK for s in status.values()), status
    kinds = {e.kind for e in result.evidence}
    assert {"dns_record", "hostname", "rdap_domain", "m365_tenant", "ip_network", "ip_cloud"} <= kinds
    assert any(e.kind == "ip_cloud" and e.data["providers"] == ["aws"] for e in result.evidence)
    ids = [e.id for e in result.evidence]
    assert len(ids) == len(set(ids))


def test_one_dead_source_does_not_stop_the_rest():
    routes = [("crt.sh", (502, b"")), ("certspotter", (503, b"")), *ROUTES[1:]]
    result = Pipeline(discovery_sources()).run(make_ctx(ZONE, routes)[0])
    status = {h.source: h.status for h in result.health}
    assert status["ct"] is Health.FAILED and status["rdap"] is Health.OK
    assert [h.source for h in result.failed()] == ["ct"]


def test_no_discovery_request_ever_targets_the_prospect():
    ctx, api = make_ctx(ZONE, ROUTES)
    Pipeline(discovery_sources()).run(ctx)
    from urllib.parse import urlsplit
    for url in api.calls:
        host = urlsplit(url).hostname
        assert host != "example.com" and not host.endswith(".example.com"), url
