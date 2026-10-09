import socket
import ssl
import threading

import pytest

from reconbrief.http import HttpClient
from reconbrief.models import Evidence, Health, Tri
from reconbrief.sources.certinfo import host_matches, parse_certificate
from reconbrief.sources.dns_records import M365_NAMES
from reconbrief.sources.pages import MAX_PAGE_HOSTS, PageLoader, classify, select_hosts
from tests.certs import make_cert
from tests.helpers import FakeHttp, make_ctx, recorded, response

HTML = [("Content-Type", "text/html; charset=utf-8"), ("Server", "Apache/2.4.6 (CentOS) PHP/5.4.16"),
        ("Set-Cookie", "sid=abc; Secure"), ("Set-Cookie", "pref=1")]


def host_dns(host, addresses=("93.184.216.34",), chain=None, wildcard=None, state=Tri.FOUND):
    return Evidence(f"hd:{host}", "host_resolution", "host_dns", host, state,
                    {"addresses": list(addresses), "chain": chain or [host], "matches_wildcard": wildcard})


def pages(result):
    return {e.subject: e for e in result.evidence if e.kind == "web_page"}


def site(host, body=None, status=200, headers=HTML, robots=None, **extra):
    """Routes for one host: robots.txt (404 unless given) and its root page."""
    robots_resp = response(404) if robots is None else response(200, robots.encode())
    page = response(status, body if body is not None else recorded("home_example.html"), headers=headers,
                    final_url=f"https://{host}/", **extra)
    return [(f"https://{host}/robots.txt", robots_resp), (f"https://{host}/", page)]


def run(routes, evidence=()):
    http = FakeHttp(routes)
    result = PageLoader().run(make_ctx(http=http, evidence=evidence))
    return result, http


# ---- what gets recorded for a page

def test_root_page_signals_banners_and_cookies():
    result, http = run(site("example.com"))
    page = pages(result)["example.com"]
    assert result.health is Health.OK and page.state is Tri.FOUND and page.data["live"] is True
    assert page.data["title"] == "Example Corp | Secure payments" and page.data["og_site_name"] == "Example Corp"
    assert page.data["has_password_form"] is True and page.data["error_class"] == "ok"
    assert {(b["product"], b["version"], b["distro"]) for b in page.data["banners"]} == \
        {("Apache", "2.4.6", "redhat"), ("PHP", "5.4.16", "redhat")}
    assert page.data["set_cookie_names"] == ["pref", "sid"]
    assert page.data["certification_mentions"] == ["SOC 2 Type 2", "ISO 27001"]
    assert page.data["vendor_mentions"] == []  # "Get the Example advantage" and a script string name no vendor
    assert page.data["robots"] == "absent" and len(page.data["body_sha256"]) == 64
    assert http.requested == ["https://example.com/robots.txt", "https://example.com/"]  # no crawl


def test_the_page_headers_are_kept_for_later_rules():
    page = pages(run(site("example.com"))[0])["example.com"]
    assert ["Server", "Apache/2.4.6 (CentOS) PHP/5.4.16"] in page.data["headers"]


# ---- robots.txt

def test_robots_disallow_means_the_page_is_not_loaded():
    result, http = run(site("example.com", robots="User-agent: *\nDisallow: /"))
    page = pages(result)["example.com"]
    assert page.state is Tri.UNKNOWN and page.data["error_class"] == "robots_blocked"
    assert "https://example.com/" not in http.requested


def test_robots_for_other_agents_does_not_block_us():
    result, _ = run(site("example.com", robots="User-agent: BadBot\nDisallow: /"))
    assert pages(result)["example.com"].state is Tri.FOUND


def test_robots_server_error_means_do_not_crawl():
    routes = [("https://example.com/robots.txt", response(503)), *site("example.com")[1:]]
    result, http = run(routes)
    assert pages(result)["example.com"].state is Tri.UNKNOWN and "https://example.com/" not in http.requested
    assert "HTTP 503" in pages(result)["example.com"].data["robots_note"]


def test_robots_unreachable_does_not_hide_the_page_and_is_not_recorded_as_absent():
    routes = [("https://example.com/robots.txt", response(error="timeout")), *site("example.com")[1:]]
    page = pages(run(routes)[0])["example.com"]
    assert page.state is Tri.FOUND and page.data["robots"] == "unknown" and "timeout" in page.data["robots_note"]


def test_robots_404_is_recorded_as_absent():
    assert pages(run(site("example.com"))[0])["example.com"].data["robots"] == "absent"


# ---- error classes and fallbacks

@pytest.mark.parametrize("fetch, expected", [
    (response(200), "ok"), (response(301), "redirect"), (response(403), "client_error"), (response(404), "client_error"),
    (response(503), "server_error"), (response(error="timeout"), "timeout"), (response(error="tls_failed"), "tls_handshake_failed"),
    (response(error="unresolved"), "dns_no_address"), (response(error="blocked_address"), "internal_address"),
    (response(error="connect_failed"), "connection_refused_or_unreachable"), (response(error="too_many_redirects"), "redirect_loop"),
])
def test_error_classes(fetch, expected):
    assert classify(fetch) == expected


def test_https_failure_falls_back_to_plain_http():
    routes = [("https://example.com/robots.txt", response(404)), ("https://example.com/", response(error="tls_failed")),
              ("http://example.com/", response(200, b"<title>old site</title>", headers=HTML, final_url="http://example.com/"))]
    result, _ = run(routes)
    page = pages(result)["example.com"]
    assert page.state is Tri.FOUND and page.data["scheme"] == "http" and page.data["title"] == "old site"
    cert = [e for e in result.evidence if e.kind == "certificate"]
    assert cert == []  # no certificate on a plain-HTTP page, and no claim about one


def test_tls_failure_is_a_certificate_unknown_not_a_finding():
    routes = [("https://example.com/robots.txt", response(404)), ("https://example.com/", response(error="tls_failed")),
              ("http://example.com/", response(error="connect_failed"))]
    result, _ = run(routes)
    assert pages(result)["example.com"].state is Tri.UNKNOWN
    cert = next(e for e in result.evidence if e.kind == "certificate")
    assert cert.state is Tri.UNKNOWN and result.health is Health.FAILED


def test_internal_addresses_are_recorded_and_never_fetched():
    routes = [("https://example.com/robots.txt", response(error="blocked_address", internal_addresses=("10.0.0.5",))),
              ("https://example.com/", response(error="blocked_address", internal_addresses=("10.0.0.5",)))]
    page = pages(run(routes)[0])["example.com"]
    assert page.data["error_class"] == "internal_address" and page.data["internal_addresses"] == ["10.0.0.5"]


def test_unresolved_host_is_absent_and_does_not_fail_the_source():
    routes = [("https://example.com/robots.txt", response(error="unresolved")), ("https://example.com/", response(error="unresolved"))]
    result, _ = run(routes)
    assert pages(result)["example.com"].state is Tri.ABSENT and result.health is Health.OK


# ---- certificates

def test_expired_certificate_is_recorded_as_expired():
    der, _, _ = make_cert("expired.example.com", -400, -35, issuer_cn="Test CA", sans=["expired.example.com"])
    routes = site("expired.example.com", peer_cert_der=der)
    result, _ = run(routes, [host_dns("expired.example.com")])
    cert = next(e for e in result.evidence if e.kind == "certificate" and e.subject == "expired.example.com")
    assert cert.state is Tri.FOUND and cert.data["expired"] is True and cert.data["days_left"] < 0
    assert cert.data["self_signed"] is False and cert.data["name_matches_host"] is True
    assert pages(result)["expired.example.com"].state is Tri.FOUND  # the page is still read


def test_expired_self_signed_certificate_from_a_real_tls_handshake(tmp_path):
    der, cert_pem, key_pem = make_cert("expired.example.com", -400, -35, sans=["expired.example.com"])
    pem = tmp_path / "server.pem"
    pem.write_bytes(cert_pem + key_pem)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(pem))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve():
        conn, _ = listener.accept()
        try:
            with server_ctx.wrap_socket(conn, server_side=True):
                pass
        except (ssl.SSLError, OSError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    sock = socket.create_connection(("127.0.0.1", listener.getsockname()[1]), timeout=5)
    wrapped, peer_der = HttpClient()._wrap_tls(sock, "expired.example.com")  # verification is off: the handshake succeeds
    wrapped.close()
    thread.join(timeout=5)
    listener.close()
    assert peer_der == der
    info = parse_certificate(peer_der, "expired.example.com")
    assert info["expired"] is True and info["self_signed"] is True and info["name_matches_host"] is True


def test_valid_certificate_and_name_mismatch():
    der, _, _ = make_cert("wrong.example.net", -10, 80, issuer_cn="Test CA", sans=["wrong.example.net", "*.example.net"])
    info = parse_certificate(der, "www.example.com")
    assert info["expired"] is False and 79 <= info["days_left"] <= 80 and info["name_matches_host"] is False
    assert info["key_type"] == "RSA" and info["key_bits"] == 2048 and info["issuer_cn"] == "Test CA"


def test_wildcard_name_matching():
    assert host_matches("a.example.com", ["*.example.com"])
    assert not host_matches("a.b.example.com", ["*.example.com"])
    assert not host_matches("example.com", ["*.example.com"])


# ---- which hosts, in what order

def hosts_of(ctx_evidence, domain="example.com"):
    return select_hosts(make_ctx(domain, evidence=ctx_evidence))


def test_hosts_run_in_order_seeds_www_normal_then_wildcard():
    ev = [host_dns("www.example.com"), host_dns("zeta.example.com"), host_dns("alpha.example.com"),
          host_dns("w1.example.com", wildcard=True), host_dns("example.com")]
    hosts, skipped, capped = hosts_of(ev)
    assert hosts == ["example.com", "www.example.com", "alpha.example.com", "zeta.example.com", "w1.example.com"]
    assert not capped and skipped == 0


def test_hosts_are_capped_at_fifty_with_wildcard_hosts_dropped_first():
    ev = [host_dns(f"h{i:02d}.example.com") for i in range(30)] + [host_dns(f"w{i:02d}.example.com", wildcard=True) for i in range(30)]
    hosts, _, capped = hosts_of(ev)
    assert len(hosts) == MAX_PAGE_HOSTS and capped
    assert sum(h.startswith("h") for h in hosts) == 30 and sum(h.startswith("w") for h in hosts) == 19


def test_hosts_without_addresses_or_outside_the_domain_are_not_loaded():
    ev = [host_dns("dead.example.com", addresses=(), state=Tri.ABSENT), host_dns("up.example.com"),
          host_dns("elsewhere.example.net")]
    assert hosts_of(ev)[0] == ["example.com", "up.example.com"]


def test_microsoft_service_names_are_not_loaded():
    ev = [host_dns("autodiscover.example.com", chain=["autodiscover.example.com", "autodiscover.outlook.com"]),
          host_dns("sip.example.com", chain=["sip.example.com", "sipdir.online.lync.com"]),
          host_dns("autodiscover2.example.com"), host_dns("app.example.com")]
    hosts, skipped, _ = hosts_of(ev)
    assert "autodiscover.example.com" not in hosts and "sip.example.com" not in hosts
    assert "app.example.com" in hosts and "autodiscover2.example.com" in hosts and skipped == 2
    assert "autodiscover" in M365_NAMES


# ---- wildcard hosts

def wildcard_ev():
    return Evidence("w", "dns_records", "wildcard", "example.com", Tri.FOUND, {"addresses": ["203.0.113.7"]})


def wildcard_routes(real_body):
    parked = b"<title>Parked</title><p>This domain is parked</p>"
    return [*site("example.com"),
            ("https://wc-", response(200, parked, headers=HTML, final_url="https://wc/")),
            *site("real.example.com", body=real_body), *site("ghost.example.com", body=parked)]


def test_wildcard_host_is_live_only_if_its_page_differs_from_the_wildcard_page():
    ev = [wildcard_ev(), host_dns("real.example.com", wildcard=True), host_dns("ghost.example.com", wildcard=True)]
    result, _ = run(wildcard_routes(b"<title>Real app</title>"), ev)
    p = pages(result)
    assert p["real.example.com"].data["wildcard_match"] is False and p["real.example.com"].data["live"] is True
    assert p["ghost.example.com"].data["wildcard_match"] is True and p["ghost.example.com"].data["live"] is False
    assert any(e.kind == "wildcard_page" and e.state is Tri.FOUND for e in result.evidence)


def test_wildcard_liveness_is_unknown_when_the_wildcard_page_cannot_be_loaded():
    routes = [*site("example.com"), ("https://wc-", response(error="timeout")), *site("real.example.com")]
    result, _ = run(routes, [wildcard_ev(), host_dns("real.example.com", wildcard=True)])
    assert pages(result)["real.example.com"].data["live"] is None


def test_no_wildcard_probe_when_no_host_matches_the_wildcard():
    result, http = run(site("example.com"), [wildcard_ev()])
    assert not any("wc-" in u for u in http.requested)


def test_a_dns_only_run_loads_only_the_domain_itself():
    result, http = run([])
    assert http.requested[0] == "https://example.com/robots.txt"


def test_wildcard_pages_with_no_title_are_not_assumed_identical():
    api_a, api_b = b'{"service": "alpha"}', b'{"service": "beta"}'
    json_headers = [("Content-Type", "application/json")]
    routes = [*site("example.com"), ("https://wc-", response(200, api_a, headers=json_headers, final_url="https://wc/")),
              *site("api.example.com", body=api_b, headers=json_headers), *site("echo.example.com", body=api_a, headers=json_headers)]
    ev = [wildcard_ev(), host_dns("api.example.com", wildcard=True), host_dns("echo.example.com", wildcard=True)]
    p = pages(run(routes, ev)[0])
    assert p["api.example.com"].data["wildcard_match"] is False and p["api.example.com"].data["live"] is True
    assert p["echo.example.com"].data["wildcard_match"] is True and p["echo.example.com"].data["live"] is False
