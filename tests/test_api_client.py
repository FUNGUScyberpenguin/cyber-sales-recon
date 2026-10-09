from discovery_helpers import FakeApi
from reconbrief.api import ApiClient


def test_retries_502_then_succeeds():
    fake = FakeApi([("crt.sh", [(502, b"bad gateway"), (502, b""), (200, b"[]")])])
    r = fake.client().get("https://crt.sh/?q=x")
    assert r.ok and r.attempts == 3


def test_gives_up_after_retries_and_reports_status():
    fake = FakeApi([("crt.sh", (503, b""))])
    r = fake.client().get("https://crt.sh/?q=x")
    assert not r.ok and r.status == 503 and r.attempts == 4


def test_timeout_is_an_error_not_a_status():
    fake = FakeApi([("crt.sh", TimeoutError())])
    r = fake.client().get("https://crt.sh/?q=x")
    assert r.error == "timeout" and r.status is None


def test_refuses_the_prospect_domain_and_its_subdomains():
    fake = FakeApi([("", (200, b"{}"))])
    client = fake.client()
    client.forbid("acme.com")
    assert client.get("https://acme.com/").error == "prospect_host_refused"
    assert client.get("https://www.acme.com/x").error == "prospect_host_refused"
    assert client.get("https://notacme.com/").ok
    assert fake.calls == ["https://notacme.com/"]


def test_refuses_plain_http():
    assert ApiClient(transport=lambda *a: (200, {}, b"")).get("http://crt.sh/").error == "bad_url"


def test_redirect_to_the_prospect_is_refused():
    fake = FakeApi([("vendor.example.net", (302, b"", {"Location": "https://www.acme.com/secret"})),
                    ("acme.com", (200, b"prospect page"))])
    client = fake.client()
    client.forbid("acme.com")
    r = client.get("https://vendor.example.net/lookup")
    assert r.error == "prospect_host_refused"
    assert fake.calls == ["https://vendor.example.net/lookup"]


def test_redirect_to_plain_http_is_refused_and_safe_redirect_is_followed():
    fake = FakeApi([("a.example.net", (301, b"", {"Location": "http://b.example.net/"}))])
    assert fake.client().get("https://a.example.net/").error == "bad_url"
    fake = FakeApi([("/moved", (200, b"ok")), ("a.example.net", (301, b"", {"Location": "/moved"}))])
    r = fake.client().get("https://a.example.net/start")
    assert r.ok and r.body == b"ok"


def test_redirect_loop_stops():
    fake = FakeApi([("a.example.net", (302, b"", {"Location": "/again"}))])
    assert fake.client().get("https://a.example.net/").error == "too_many_redirects"
