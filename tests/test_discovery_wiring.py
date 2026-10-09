from reconbrief.models import Health, Tri
from reconbrief.pipeline import Pipeline
from reconbrief.sources import discovery_sources
from reconbrief.sources.certificates import CertificateTransparency
from tests.helpers import FakeHttp, ScriptedDns, make_ctx, recorded, response
from tests.test_dns_source import base_answers


def test_full_discovery_run_orders_stages_and_survives_failures():
    answers = base_answers()
    answers[("dev.example.com", "A")] = ["52.95.1.1"]
    answers[("old.example.com", "CNAME")] = ["gone.thirdparty.io."]
    http = FakeHttp([
        ("https://crt.sh/", response(502)),
        ("https://api.certspotter.com/", response(200, b"[]")),
        ("https://rdap.org/", recorded("rdap_example_com.json")),
        ("https://web.archive.org/", recorded("wayback_cdx.json")),
        ("https://urlscan.io/", response(429)),
        ("https://login.microsoftonline.com/getuserrealm", recorded("m365_realm_unknown.json")),
        ("https://ip-ranges.amazonaws.com/", recorded("aws_ranges_subset.json")),
        ("https://www.gstatic.com/", recorded("gcp_ranges_subset.json")),
        ("https://www.cloudflare.com/ips-v4", recorded("cloudflare_v4.txt")),
        ("https://www.cloudflare.com/ips-v6", recorded("cloudflare_v6.txt")),
        ("https://stat.ripe.net/", recorded("ripestat_prefix.json")),
    ])
    sources = [CertificateTransparency(sleep=lambda s: None) if s.name == "certificate_transparency" else s
               for s in discovery_sources()]
    result = Pipeline(sources).run(make_ctx(dns=ScriptedDns(answers), http=http))
    health = {h.source: h.status for h in result.health}
    assert health["urlscan"] is Health.FAILED
    assert health["rdap"] is Health.OK and health["host_resolution"] is Health.OK
    assert {"dangling_cname"} <= {e.kind for e in result.evidence}  # wayback's old.example.com was resolved in stage 2
    assert any(e.kind == "cloud_range" and e.state is Tri.FOUND for e in result.evidence)
    ids = [e.id for e in result.evidence]
    assert len(ids) == len(set(ids))
