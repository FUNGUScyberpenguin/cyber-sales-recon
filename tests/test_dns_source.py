import json

from reconbrief.models import Health, Tri
from reconbrief.sources.dns_records import DnsRecords, HostResolution, resolve_chain
from tests.helpers import ScriptedDns, make_ctx, recorded
from reconbrief.models import Evidence


def by_kind(result, kind):
    return {e.subject: e for e in result.evidence if e.kind == kind}


def base_answers():
    raw = json.loads(recorded("dns_example_com.json"))
    return {(k.split("|")[0], k.split("|")[1]): v for k, v in raw.items()}


def test_records_mail_policy_and_m365_names():
    result = DnsRecords().run(make_ctx(dns=ScriptedDns(base_answers())))
    assert result.health is Health.OK
    records = by_kind(result, "dns_record")
    assert records["example.com NS"].state is Tri.FOUND
    assert by_kind(result, "spf")["example.com"].state is Tri.FOUND
    assert by_kind(result, "dmarc")["_dmarc.example.com"].data["records"] == ["v=DMARC1; p=none"]
    assert by_kind(result, "mta_sts")["_mta-sts.example.com"].state is Tri.FOUND
    assert by_kind(result, "tls_rpt")["_smtp._tls.example.com"].state is Tri.ABSENT
    dkim = by_kind(result, "dkim")["example.com"]
    assert dkim.state is Tri.FOUND and dkim.data["selectors_found"] == ["google"]
    m365 = by_kind(result, "m365_name")
    assert m365["autodiscover.example.com"].data["points_to_microsoft"] is True
    assert m365["lyncdiscover.example.com"].data["points_to_microsoft"] is True
    assert m365["msoid.example.com"].state is Tri.ABSENT


def test_unknown_spf_is_unknown_not_absent():
    dns = ScriptedDns(base_answers(), unknown={("example.com", "TXT")})
    result = DnsRecords().run(make_ctx(dns=dns))
    assert by_kind(result, "spf")["example.com"].state is Tri.UNKNOWN
    assert result.health is Health.PARTIAL
    assert "not checked" in result.detail


def test_txt_without_spf_is_absent():
    answers = base_answers()
    answers[("example.com", "TXT")] = ["google-site-verification=abc"]
    result = DnsRecords().run(make_ctx(dns=ScriptedDns(answers)))
    assert by_kind(result, "spf")["example.com"].state is Tri.ABSENT


def test_all_core_lookups_failing_marks_source_failed():
    dns = ScriptedDns(unknown={("example.com", t) for t in ("A", "AAAA", "NS", "MX")})
    assert DnsRecords().run(make_ctx(dns=dns)).health is Health.FAILED


def test_wildcard_detected_and_absent():
    wild = base_answers()
    ctx_dns = ScriptedDns(wild)
    ctx_dns.query_orig = ctx_dns.query

    def query(name, rdtype):
        if name.startswith("wc-") and rdtype == "A":
            from reconbrief.resolver import DnsResult
            return DnsResult(Tri.FOUND, ("203.0.113.9",))
        return ctx_dns.query_orig(name, rdtype)

    ctx_dns.query = query
    assert by_kind(DnsRecords().run(make_ctx(dns=ctx_dns)), "wildcard")["example.com"].data["addresses"] == ["203.0.113.9"]
    assert by_kind(DnsRecords().run(make_ctx(dns=ScriptedDns(base_answers()))), "wildcard")["example.com"].state is Tri.ABSENT


def test_cname_chain_and_dangling_target():
    dns = ScriptedDns({("shop.example.com", "CNAME"): ["shops.thirdparty.io."]})
    chain = resolve_chain(dns, "shop.example.com")
    assert chain.chain == ["shop.example.com", "shops.thirdparty.io"]
    assert chain.dangling_target == "shops.thirdparty.io"


def test_cname_to_target_that_exists_is_not_dangling():
    dns = ScriptedDns({("shop.example.com", "CNAME"): ["shops.thirdparty.io."],
                       ("shops.thirdparty.io", "A"): ["198.51.100.7"]})
    chain = resolve_chain(dns, "shop.example.com")
    assert chain.dangling_target == "" and chain.addresses == ("198.51.100.7",)


def test_failed_target_lookup_is_not_dangling():
    dns = ScriptedDns({("shop.example.com", "CNAME"): ["shops.thirdparty.io."]},
                      unknown={("shops.thirdparty.io", "A")})
    chain = resolve_chain(dns, "shop.example.com")
    assert chain.state is Tri.UNKNOWN and chain.dangling_target == ""


def test_host_resolution_flags_wildcard_matches_and_dangling():
    dns = ScriptedDns({
        ("a.example.com", "A"): ["203.0.113.9"],
        ("b.example.com", "A"): ["198.51.100.1"],
        ("c.example.com", "CNAME"): ["gone.thirdparty.io."],
    })
    seed = [
        Evidence("w", "dns_records", "wildcard", "example.com", Tri.FOUND, {"addresses": ["203.0.113.9"]}),
        Evidence("1", "wayback", "archive_hostname", "a.example.com", Tri.FOUND),
        Evidence("2", "certificate_transparency", "ct_hostname", "b.example.com", Tri.FOUND),
        Evidence("3", "urlscan", "urlscan_hostname", "c.example.com", Tri.FOUND),
        Evidence("4", "certificate_transparency", "ct_hostname", "c.example.com", Tri.FOUND),
    ]
    result = HostResolution().run(make_ctx(dns=dns, evidence=seed))
    hosts = by_kind(result, "host_dns")
    assert hosts["a.example.com"].data["matches_wildcard"] is True
    assert hosts["b.example.com"].data["matches_wildcard"] is False
    assert hosts["c.example.com"].data["seen_by"] == ["certificate_transparency", "urlscan"]
    assert by_kind(result, "dangling_cname")["c.example.com"].data["target"] == "gone.thirdparty.io"


def test_unknown_wildcard_probe_leaves_wildcard_match_unknown():
    dns = ScriptedDns({("a.example.com", "A"): ["203.0.113.9"]})
    seed = [
        Evidence("w", "dns_records", "wildcard", "example.com", Tri.UNKNOWN, {"error": "timeout"}),
        Evidence("1", "wayback", "archive_hostname", "a.example.com", Tri.FOUND),
    ]
    result = HostResolution().run(make_ctx(dns=dns, evidence=seed))
    assert by_kind(result, "host_dns")["a.example.com"].data["matches_wildcard"] is None
    assert "wildcard not checked" in result.detail
