import json

from reconbrief.models import Health, Tri
from reconbrief.sources.certificates import CertificateTransparency
from reconbrief.sources.history import Urlscan, Wayback
from reconbrief.sources.rdap import Rdap, normalize_status
from tests.helpers import FakeHttp, make_ctx, recorded, response

CRT = "https://crt.sh/"
SPOTTER = "https://api.certspotter.com/v1/issuances"


def hosts(result):
    return {e.subject: e for e in result.evidence if e.kind == "ct_hostname"}


def run_ct(routes, sleeps=None):
    sleeps = [] if sleeps is None else sleeps
    return CertificateTransparency(sleep=sleeps.append).run(make_ctx(http=FakeHttp(routes))), sleeps


def test_crtsh_hostnames_scoped_to_the_domain():
    result, _ = run_ct([(CRT, recorded("crtsh_example.json"))])
    found = hosts(result)
    assert set(found) == {"example.com", "www.example.com", "staging.example.com", "vpn.example.com"}
    assert found["example.com"].data["wildcard_cert"] is True
    assert found["staging.example.com"].data["issuers"] == ["C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1"]
    assert result.health is Health.OK


def test_crtsh_502_falls_back_to_cert_spotter():
    def pages(url):
        return response(200, recorded("certspotter_page2.json" if "after=1002" in url else "certspotter_page1.json"))

    result, sleeps = run_ct([(CRT, response(502)), (SPOTTER, pages)])
    assert set(hosts(result)) == {"example.com", "www.example.com", "staging.example.com"}
    assert hosts(result)["example.com"].data["provider"] == "certspotter"
    assert "used Cert Spotter instead" in result.detail
    assert len(sleeps) == 3  # crt.sh was retried with backoff before giving up
    assert result.health is Health.OK


def test_crtsh_retry_can_succeed():
    calls = []

    def flaky(url):
        calls.append(url)
        return response(502) if len(calls) < 3 else response(200, recorded("crtsh_example.json"))

    result, sleeps = run_ct([(CRT, flaky)])
    assert len(hosts(result)) == 4 and len(sleeps) == 2


def test_both_ct_sources_failing_is_failed_with_no_evidence():
    result, _ = run_ct([(CRT, response(502)), (SPOTTER, response(429))])
    assert result.health is Health.FAILED and result.evidence == []


def test_cert_spotter_stopped_midway_is_partial():
    def pages(url):
        return response(429) if "after=" in url else response(200, recorded("certspotter_page1.json"))

    result, _ = run_ct([(CRT, response(503)), (SPOTTER, pages)])
    assert result.health is Health.PARTIAL and hosts(result)


def test_oversized_crtsh_response_falls_back_instead_of_parsing_half_a_document():
    big = response(200, b"[{", )
    big.truncated = True
    result, _ = run_ct([(CRT, big), (SPOTTER, response(200, b"[]"))])
    assert "crt.sh failed" in result.detail


def test_empty_ct_answer_is_absent():
    result, _ = run_ct([(CRT, b"[]")])
    summary = next(e for e in result.evidence if e.kind == "ct_summary")
    assert summary.state is Tri.ABSENT


def test_locked_com_shows_transfer_lock_true():
    result = Rdap().run(make_ctx(http=FakeHttp([("https://rdap.org/", recorded("rdap_example_com.json"))])))
    data = result.evidence[0].data
    assert data["transfer_lock"] is True
    assert data["statuses"] == ["clientdeleteprohibited", "clienttransferprohibited", "clientupdateprohibited"]
    assert data["registrar"] == "Example Registrar, Inc."
    assert data["registrant_org"] == ""  # redacted, so not trusted
    assert data["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert data["age_days"] > 365 * 30


def test_unlocked_domain_and_unredacted_org():
    result = Rdap().run(make_ctx(http=FakeHttp([("https://rdap.org/", recorded("rdap_unlocked_with_org.json"))])))
    data = result.evidence[0].data
    assert data["transfer_lock"] is False
    assert data["registrant_org"] == "Acme Industrial Holdings LLC"


def test_status_normalization():
    for text in ("clientTransferProhibited", "client transfer prohibited", "client-transfer-prohibited", "CLIENT_TRANSFER_PROHIBITED"):
        assert normalize_status(text) == "clienttransferprohibited"


def test_rdap_failure_is_unknown_and_never_says_unlocked():
    result = Rdap().run(make_ctx(http=FakeHttp([("https://rdap.org/", response(503))])))
    assert result.health is Health.FAILED
    assert result.evidence[0].state is Tri.UNKNOWN and "transfer_lock" not in result.evidence[0].data


def test_wayback_hostnames():
    result = Wayback().run(make_ctx(http=FakeHttp([("https://web.archive.org/", recorded("wayback_cdx.json"))])))
    found = {e.subject: e.data["observations"] for e in result.evidence}
    assert found == {"example.com": 1, "old.example.com": 2, "dev.example.com": 1, "www.example.com": 1}


def test_urlscan_hostnames_ignore_other_domains():
    result = Urlscan().run(make_ctx(http=FakeHttp([("https://urlscan.io/", recorded("urlscan.json"))])))
    assert {e.subject for e in result.evidence} == {"portal.example.com", "www.example.com", "example.com"}


def test_history_failure_reports_failed_not_empty():
    http = FakeHttp([("https://web.archive.org/", response(error="timeout")), ("https://urlscan.io/", response(429))])
    for source in (Wayback(), Urlscan()):
        result = source.run(make_ctx(http=http))
        assert result.health is Health.FAILED and result.evidence == []
