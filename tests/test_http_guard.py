import io
import socket

import pytest

from reconbrief.http import USER_AGENT, AddressGuard, HttpClient
from reconbrief.models import Tri
from reconbrief.resolver import DnsResult

PUBLIC = "93.184.216.34"
OTHER_PUBLIC = "8.8.8.8"


class FakeResolver:
    def __init__(self, table):
        self.table = table

    def query(self, name, rdtype):
        records = self.table.get((name, rdtype))
        if records is None:
            return DnsResult(Tri.ABSENT, error="NXDOMAIN")
        if records == "timeout":
            return DnsResult(Tri.UNKNOWN, error="timeout")
        return DnsResult(Tri.FOUND, tuple(records))


class FakeSocket:
    def __init__(self, response: bytes):
        self.response = response
        self.sent = b""

    def sendall(self, data):
        self.sent += data

    def makefile(self, *a, **k):
        return io.BytesIO(self.response)

    def settimeout(self, t):
        pass

    def close(self):
        pass


def http(status="200 OK", extra="", body=b"hi"):
    return (f"HTTP/1.1 {status}\r\n{extra}Content-Length: {len(body)}\r\n\r\n").encode() + body


@pytest.fixture
def connections(monkeypatch):
    """Record every connect attempt. Responses are queued per test."""
    log = {"connects": [], "responses": []}

    def fake_connect(addr, timeout=None, **kw):
        log["connects"].append(addr)
        sock = FakeSocket(log["responses"].pop(0))
        log.setdefault("sockets", []).append(sock)
        return sock

    monkeypatch.setattr(socket, "create_connection", fake_connect)
    return log


def client(table=None):
    return HttpClient(AddressGuard(FakeResolver(table or {})), timeout=1)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "::ffff:127.0.0.1",
                                "192.168.1.1", "100.64.0.1", "0.0.0.0"])
def test_literal_non_global_addresses_never_connect(connections, ip):
    host = f"[{ip}]" if ":" in ip else ip
    result = client().fetch(f"http://{host}/")
    assert result.error == "blocked_address"
    assert result.state is Tri.UNKNOWN
    assert connections["connects"] == []


def test_hostname_resolving_only_to_internal_addresses_never_connects(connections):
    table = {("intranet.example.com", "A"): ["10.0.0.5"], ("intranet.example.com", "AAAA"): ["fd00::1"]}
    result = client(table).fetch("https://intranet.example.com/")
    assert result.error == "blocked_address"
    assert set(result.internal_addresses) == {"10.0.0.5", "fd00::1"}
    assert connections["connects"] == []


def test_mixed_answer_connects_only_to_the_global_address(connections):
    connections["responses"].append(http())
    table = {("mixed.example.com", "A"): ["10.0.0.5", PUBLIC]}
    result = client(table).fetch("http://mixed.example.com/")
    assert result.ok and connections["connects"] == [(PUBLIC, 80)]
    assert result.internal_addresses == ("10.0.0.5",)


def test_connects_to_checked_address_and_keeps_host_header_and_user_agent(connections):
    connections["responses"].append(http(body=b"hello"))
    result = client({("www.example.com", "A"): [PUBLIC]}).fetch("http://www.example.com/a?b=1")
    sent = connections["sockets"][0].sent.decode()
    assert connections["connects"] == [(PUBLIC, 80)]
    assert "GET /a?b=1 HTTP/1.1" in sent
    assert "Host: www.example.com\r\n" in sent
    assert f"User-Agent: {USER_AGENT}" in sent
    assert result.body == b"hello" and result.state is Tri.FOUND


def test_user_agent_names_tool_version_and_repo():
    import reconbrief
    assert f"reconbrief/{reconbrief.__version__}" in USER_AGENT
    assert "github.com/FUNGUScyberpenguin/cyber-sales-recon" in USER_AGENT


def test_https_uses_hostname_for_sni_and_records_cert(connections, monkeypatch):
    connections["responses"].append(http())
    c = client({("www.example.com", "A"): [PUBLIC]})
    seen = {}

    def fake_wrap(sock, host):
        seen["host"] = host
        return sock, b"der-bytes"

    monkeypatch.setattr(c, "_wrap_tls", fake_wrap)
    result = c.fetch("https://www.example.com/")
    assert seen["host"] == "www.example.com"
    assert connections["connects"] == [(PUBLIC, 443)]
    assert result.peer_cert_der == b"der-bytes"
    assert "Host: www.example.com\r\n" in connections["sockets"][0].sent.decode()


def test_redirect_to_internal_address_is_blocked_before_connecting(connections):
    connections["responses"].append(http("302 Found", "Location: http://127.0.0.1/admin\r\n"))
    result = client({("www.example.com", "A"): [PUBLIC]}).fetch("http://www.example.com/")
    assert result.error == "blocked_address"
    assert connections["connects"] == [(PUBLIC, 80)]  # the first hop only


def test_redirect_to_hostname_that_resolves_internal_is_blocked(connections):
    connections["responses"].append(http("301 Moved", "Location: http://metadata.example.com/\r\n"))
    table = {("www.example.com", "A"): [PUBLIC], ("metadata.example.com", "A"): ["169.254.169.254"]}
    result = client(table).fetch("http://www.example.com/")
    assert result.error == "blocked_address"
    assert connections["connects"] == [(PUBLIC, 80)]


def test_redirect_to_another_public_host_is_checked_and_followed(connections):
    connections["responses"].append(http("302 Found", "Location: http://other.example.org/x\r\n"))
    connections["responses"].append(http(body=b"done"))
    table = {("www.example.com", "A"): [PUBLIC], ("other.example.org", "A"): [OTHER_PUBLIC]}
    result = client(table).fetch("http://www.example.com/")
    assert result.ok and result.body == b"done"
    assert connections["connects"] == [(PUBLIC, 80), (OTHER_PUBLIC, 80)]
    assert result.redirects == ["http://www.example.com/"]
    assert result.final_url == "http://other.example.org/x"


def test_redirect_loop_stops(connections):
    for _ in range(10):
        connections["responses"].append(http("302 Found", "Location: http://www.example.com/\r\n"))
    c = client({("www.example.com", "A"): [PUBLIC]})
    assert c.fetch("http://www.example.com/").error == "too_many_redirects"


def test_redirect_to_odd_port_is_blocked(connections):
    connections["responses"].append(http("302 Found", "Location: http://www.example.com:22/\r\n"))
    result = client({("www.example.com", "A"): [PUBLIC]}).fetch("http://www.example.com/")
    assert result.error == "blocked_port" and len(connections["connects"]) == 1


def test_failed_address_lookup_is_unknown_and_missing_host_is_absent(connections):
    unknown = client({("a.example.com", "A"): "timeout", ("a.example.com", "AAAA"): "timeout"})
    assert unknown.fetch("http://a.example.com/").state is Tri.UNKNOWN
    assert client().fetch("http://gone.example.com/").state is Tri.ABSENT
    assert connections["connects"] == []


def test_connect_failure_is_unknown(monkeypatch):
    def refuse(addr, timeout=None, **kw):
        raise ConnectionRefusedError()

    monkeypatch.setattr(socket, "create_connection", refuse)
    result = client({("www.example.com", "A"): [PUBLIC]}).fetch("http://www.example.com/")
    assert result.error == "connect_failed" and result.state is Tri.UNKNOWN
