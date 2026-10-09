from reconbrief.models import Evidence, Health, Tri
from reconbrief.sources.network import CloudRanges, M365Tenant, RipeStat, public_ips
from tests.helpers import FakeHttp, make_ctx, recorded, response

AWS, GCP = "https://ip-ranges.amazonaws.com/", "https://www.gstatic.com/ipranges/"
CF4, CF6 = "https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"


def ips_evidence(*ips):
    return [Evidence("d", "dns_records", "dns_record", "example.com A", Tri.FOUND, {"records": list(ips)})]


def cloud_routes():
    return [(AWS, recorded("aws_ranges_subset.json")), (GCP, recorded("gcp_ranges_subset.json")),
            (CF4, recorded("cloudflare_v4.txt")), (CF6, recorded("cloudflare_v6.txt"))]


def test_tenant_found_with_id():
    http = FakeHttp([("https://login.microsoftonline.com/getuserrealm", recorded("m365_realm_managed.json")),
                     ("https://login.microsoftonline.com/example.com/", recorded("m365_openid.json"))])
    result = M365Tenant().run(make_ctx(http=http))
    data = result.evidence[0].data
    assert result.evidence[0].state is Tri.FOUND and data["namespace_type"] == "Managed"
    assert data["tenant_id"] == "72f988bf-86f1-41af-91ab-2d7cd011db47"


def test_unknown_namespace_means_no_tenant():
    http = FakeHttp([("https://login.microsoftonline.com/getuserrealm", recorded("m365_realm_unknown.json"))])
    assert M365Tenant().run(make_ctx(http=http)).evidence[0].state is Tri.ABSENT


def test_tenant_lookup_failure_is_unknown():
    http = FakeHttp([("https://login.microsoftonline.com/", response(error="timeout"))])
    result = M365Tenant().run(make_ctx(http=http))
    assert result.health is Health.FAILED and result.evidence[0].state is Tri.UNKNOWN


def test_public_ips_skip_private_addresses():
    ev = ips_evidence("93.184.216.34", "10.0.0.5", "not-an-ip")
    assert public_ips(make_ctx(evidence=ev)) == ["93.184.216.34"]


def test_cloud_ranges_match_providers_and_miss_others():
    ev = ips_evidence("52.95.1.1", "34.64.1.1", "104.16.5.5", "93.184.216.34")
    result = CloudRanges().run(make_ctx(http=FakeHttp(cloud_routes()), evidence=ev))
    by_ip = {e.subject: e for e in result.evidence}
    assert by_ip["52.95.1.1"].data["provider"] == "aws" and by_ip["52.95.1.1"].data["service"] == "EC2"
    assert by_ip["34.64.1.1"].data["provider"] == "gcp"
    assert by_ip["104.16.5.5"].data["provider"] == "cloudflare"
    assert by_ip["93.184.216.34"].state is Tri.ABSENT
    assert result.health is Health.OK


def test_cloud_ranges_with_a_failed_list_do_not_claim_absence():
    routes = [r for r in cloud_routes() if not r[0].startswith(AWS)]
    result = CloudRanges().run(make_ctx(http=FakeHttp(routes), evidence=ips_evidence("93.184.216.34")))
    assert result.evidence[0].state is Tri.UNKNOWN
    assert result.health is Health.PARTIAL and "aws" in result.detail


def test_cloud_ranges_skipped_without_addresses():
    assert CloudRanges().run(make_ctx(http=FakeHttp(cloud_routes()))).health is Health.SKIPPED


def test_ripestat_owner():
    http = FakeHttp([("https://stat.ripe.net/", recorded("ripestat_prefix.json"))])
    result = RipeStat().run(make_ctx(http=http, evidence=ips_evidence("93.184.216.34")))
    data = result.evidence[0].data
    assert data["asn"] == 15133 and data["prefix"] == "93.184.216.0/24" and "Edgecast" in data["holder"]


def test_ripestat_failure_is_unknown():
    http = FakeHttp([("https://stat.ripe.net/", response(503))])
    result = RipeStat().run(make_ctx(http=http, evidence=ips_evidence("93.184.216.34")))
    assert result.evidence[0].state is Tri.UNKNOWN and result.health is Health.FAILED
