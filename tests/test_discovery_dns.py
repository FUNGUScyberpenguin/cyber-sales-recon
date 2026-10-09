from discovery_helpers import make_ctx
from reconbrief.models import Health, Tri
from reconbrief.sources.dns_records import DnsRecords, HostDns

ZONE = {
    ("example.com", "A"): ["93.184.216.34"],
    ("example.com", "NS"): ["a.iana-servers.net."],
    ("example.com", "MX"): ["10 mail.example.com."],
    ("example.com", "TXT"): ["v=spf1 include:_spf.example.net ~all", "google-site-verification=abc"],
    ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
    ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=20260101"],
    ("selector1._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p=AAA"],
    ("autodiscover.example.com", "CNAME"): ["autodiscover.outlook.com."],
    ("autodiscover.outlook.com", "A"): ["52.96.0.1"],
    ("www.example.com", "CNAME"): ["old-shop.vendor-gone.net."],
    ("vendor-gone.net", "A"): ["198.51.100.9"],
}


def by(result, kind, subject=None):
    return [e for e in result.evidence if e.kind == kind and (subject is None or e.subject == subject)]


def test_apex_records_spf_dmarc_dkim():
    ctx, _ = make_ctx(ZONE)
    r = DnsRecords().run(ctx)
    assert by(r, "dns_record", "example.com/A")[0].data["records"] == ["93.184.216.34"]
    assert by(r, "spf", "example.com")[0].state is Tri.FOUND
    assert by(r, "dmarc")[0].state is Tri.FOUND
    assert by(r, "mta_sts")[0].state is Tri.FOUND and by(r, "tls_rpt")[0].state is Tri.ABSENT
    dkim = {e.data["selector"]: e.state for e in by(r, "dkim_selector")}
    assert dkim["selector1"] is Tri.FOUND and dkim["google"] is Tri.ABSENT
    assert by(r, "caa") == [] and by(r, "dns_record", "example.com/CAA")[0].state is Tri.ABSENT


def test_unknown_spf_when_txt_lookup_times_out():
    ctx, _ = make_ctx(ZONE, fail={("example.com", "TXT")})
    r = DnsRecords().run(ctx)
    assert by(r, "spf")[0].state is Tri.UNKNOWN  # not ABSENT, so no "missing SPF" finding can follow
    assert r.health is Health.PARTIAL and "failed" in r.detail


def test_m365_name_cnamed_to_microsoft_is_tagged():
    ctx, _ = make_ctx(ZONE)
    r = DnsRecords().run(ctx)
    ad = by(r, "cname_chain", "autodiscover.example.com")[0]
    assert ad.state is Tri.FOUND and ad.data["microsoft"] and ad.data["m365_name"]
    assert by(r, "dangling_cname", "autodiscover.example.com")[0].state is Tri.ABSENT
    assert by(r, "cname_chain", "sip.example.com")[0].state is Tri.ABSENT


def test_dangling_cname_found_on_nxdomain_target():
    zone = {**ZONE, ("shop.example.com", "CNAME"): ["gone.nowhere-host.net."]}
    zone.pop(("www.example.com", "CNAME"))
    ctx, _ = make_ctx(zone)
    from reconbrief.models import Evidence
    ctx.evidence.append(Evidence("E-h", "ct", "hostname", "shop.example.com", Tri.FOUND))
    r = HostDns().run(ctx)
    d = by(r, "dangling_cname", "shop.example.com")[0]
    assert d.state is Tri.FOUND and d.data["target"] == "gone.nowhere-host.net"


def test_dangling_is_unknown_when_target_lookup_fails():
    zone = {**ZONE, ("shop.example.com", "CNAME"): ["flaky.nowhere-host.net."]}
    ctx, _ = make_ctx(zone, fail={("flaky.nowhere-host.net", "A")})
    from reconbrief.models import Evidence
    ctx.evidence.append(Evidence("E-h", "ct", "hostname", "shop.example.com", Tri.FOUND))
    r = HostDns().run(ctx)
    assert by(r, "dangling_cname", "shop.example.com")[0].state is Tri.UNKNOWN
    assert r.health is Health.PARTIAL


def test_cname_chain_is_followed():
    zone = {**ZONE, ("a.example.com", "CNAME"): ["b.cdn.example.net."], ("b.cdn.example.net", "CNAME"): ["c.edge.net."],
            ("c.edge.net", "A"): ["198.51.100.20"]}
    ctx, _ = make_ctx(zone)
    from reconbrief.models import Evidence
    ctx.evidence.append(Evidence("E-h", "ct", "hostname", "a.example.com", Tri.FOUND))
    e = by(HostDns().run(ctx), "cname_chain", "a.example.com")[0]
    assert e.data["chain"] == ["b.cdn.example.net", "c.edge.net"]


def test_wildcard_detected_and_absent():
    ctx, _ = make_ctx(ZONE, wildcard_a="203.0.113.7")
    assert by(DnsRecords().run(ctx), "wildcard")[0].state is Tri.FOUND
    ctx, _ = make_ctx(ZONE)
    assert by(DnsRecords().run(ctx), "wildcard")[0].state is Tri.ABSENT


def test_all_lookups_failing_is_a_failed_source():
    from discovery_helpers import FakeZone
    import dns.exception
    from reconbrief.pipeline import Context
    from reconbrief.resolver import DnsResolver
    from reconbrief.http import AddressGuard, HttpClient

    def boom(q, s, t, tcp):
        raise dns.exception.Timeout()

    resolver = DnsResolver(nameservers=["192.0.2.53"], transport=boom, timeout=0.1)
    ctx = Context("example.com", resolver, HttpClient(AddressGuard(resolver)))
    r = DnsRecords().run(ctx)
    assert r.health is Health.FAILED and all(e.state is Tri.UNKNOWN for e in r.evidence)
