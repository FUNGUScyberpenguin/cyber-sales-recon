import hashlib

from reconbrief.models import Evidence, Health, Tri
from reconbrief.sources.trust import TrustPosture, candidate_urls, homepage, parse_security_txt
from tests.helpers import FakeHttp, make_ctx, recorded, response

HTML = [("Content-Type", "text/html")]
TXT = [("Content-Type", "text/plain")]
HOME_BODY = recorded("home_example.html")
SEC_URL = "https://example.com/.well-known/security.txt"


def home_page(links=None, body=HOME_BODY, title="Example Corp | Secure payments", host="example.com"):
    links = links if links is not None else [{"href": "https://example.com/trust", "text": "Trust Center"}]
    return Evidence(f"wp:{host}", "page_loader", "web_page", host, Tri.FOUND,
                    {"status": 200, "title": title, "links": links, "body_sha256": hashlib.sha256(body).hexdigest()})


def run(routes, evidence):
    http = FakeHttp([("https://example.com/robots.txt", response(404)), *routes])
    result = TrustPosture().run(make_ctx(http=http, evidence=evidence))
    return result, http, {e.kind + ":" + e.subject: e for e in result.evidence}


def center(found):
    return found["trust_center:example.com"]


def trust_page_route(url="https://example.com/trust", body=None):
    return (url, response(200, body or recorded("trust_center_example.html"), headers=HTML, final_url=url))


def test_trust_center_found_from_a_homepage_link():
    result, _, found = run([trust_page_route(), (SEC_URL, response(404))], [home_page()])
    tc = center(found)
    assert tc.state is Tri.FOUND and tc.data["found_via"] == "homepage_link"
    assert tc.data["vendors"] == ["Vanta"] and tc.data["certifications"] == ["GDPR", "HIPAA", "SOC 2 Type 2"]
    assert found["trust_page:https://example.com/trust"].data["soft_404"] is False


def test_a_page_that_matches_the_homepage_is_a_soft_404_not_a_trust_center():
    soft = response(200, HOME_BODY, headers=HTML, final_url="https://example.com/trust")
    result, _, found = run([("https://example.com/trust", soft), (SEC_URL, response(404))], [home_page()])
    assert found["trust_page:https://example.com/trust"].state is Tri.ABSENT
    assert found["trust_page:https://example.com/trust"].data["soft_404"] is True
    assert center(found).state is Tri.ABSENT  # the check ran: the homepage was read and every candidate answered


def test_same_title_as_the_homepage_is_also_a_soft_404():
    other = b"<html><head><title>Example Corp | Secure payments</title></head><body>different bytes</body></html>"
    result, _, found = run([trust_page_route(body=other), (SEC_URL, response(404))], [home_page()])
    assert found["trust_page:https://example.com/trust"].data["soft_404"] is True


def test_404_trust_link_makes_the_center_absent():
    result, _, found = run([("https://example.com/trust", response(404)), (SEC_URL, response(404))], [home_page()])
    assert center(found).state is Tri.ABSENT and center(found).data["candidates_checked"] == ["https://example.com/trust"]


def test_a_candidate_that_could_not_be_fetched_leaves_the_center_unknown():
    result, _, found = run([("https://example.com/trust", response(error="timeout")), (SEC_URL, response(404))], [home_page()])
    assert center(found).state is Tri.UNKNOWN and result.health is Health.PARTIAL


def test_dns_only_run_reports_no_trust_center_absence():
    http = FakeHttp()
    result = TrustPosture().run(make_ctx(http=http))
    ev = result.evidence[0]
    assert ev.kind == "trust_center" and ev.state is Tri.UNKNOWN and result.health is Health.SKIPPED
    assert http.requested == []  # nothing was fetched without a loaded homepage


def test_failed_homepage_load_reports_no_trust_center_absence():
    failed = Evidence("wp", "page_loader", "web_page", "example.com", Tri.UNKNOWN, {"error_class": "timeout"})
    result = TrustPosture().run(make_ctx(http=FakeHttp(), evidence=[failed]))
    assert result.evidence[0].state is Tri.UNKNOWN


def test_homepage_with_no_links_is_unknown_not_absent():
    result, _, found = run([(SEC_URL, response(404))], [home_page(links=[])])
    assert center(found).state is Tri.UNKNOWN and "no links" in center(found).data["reason"]


def test_trust_and_security_hosts_found_in_discovery_are_candidates():
    ev = [home_page(links=[]), Evidence("c1", "certificate_transparency", "ct_hostname", "trust.example.com", Tri.FOUND),
          Evidence("c2", "wayback", "archive_hostname", "security.example.com", Tri.FOUND),
          Evidence("c3", "wayback", "archive_hostname", "trustworthy.example.com", Tri.FOUND),
          Evidence("c4", "wayback", "archive_hostname", "app.example.com", Tri.FOUND)]
    ctx = make_ctx(evidence=ev)
    urls = [(u, how) for u, how in candidate_urls(ctx, homepage(ctx))]
    assert urls == [("https://security.example.com/", "discovered_host"), ("https://trust.example.com/", "discovered_host")]


def test_vendor_hosted_trust_page_linked_from_the_homepage():
    links = [{"href": "https://app.safebase.io/portal/example/trust", "text": "Trust Portal"},
             {"href": "https://evil.net/trust", "text": "Trust"}, {"href": "mailto:a@example.com", "text": "security"}]
    ctx = make_ctx(evidence=[home_page(links=links)])
    assert candidate_urls(ctx, homepage(ctx)) == [("https://app.safebase.io/portal/example/trust", "homepage_link")]
    body = b"<title>Example</title><p>loading</p>"
    url = "https://app.safebase.io/portal/example/trust"
    result, _, found = run([("https://app.safebase.io/robots.txt", response(404)),
                            (url, response(200, body, headers=HTML, final_url=url)), (SEC_URL, response(404))],
                           [home_page(links=links)])
    assert center(found).state is Tri.FOUND and center(found).data["platform"] == "SafeBase"


def test_candidates_are_capped_and_ordered():
    links = [{"href": f"https://example.com/security/{i}", "text": "Security"} for i in range(12)]
    ctx = make_ctx(evidence=[home_page(links=links)])
    assert len(candidate_urls(ctx, homepage(ctx))) == 5


def test_robots_disallow_stops_a_trust_page_fetch():
    http = FakeHttp([("https://example.com/robots.txt", response(200, b"User-agent: *\nDisallow: /trust\n")),
                     ("https://example.com/trust", response(200, b"x")), (SEC_URL, response(404))])
    result = TrustPosture().run(make_ctx(http=http, evidence=[home_page()]))
    assert "https://example.com/trust" not in http.requested
    assert {e.kind: e for e in result.evidence}["trust_center"].state is Tri.UNKNOWN


# ---- security.txt

def sec(response_):
    return run([(SEC_URL, response_)], [home_page(links=[])])[2]["security_txt:example.com"]


def test_security_txt_found_and_parsed():
    ev = sec(response(200, recorded("security_txt_example.txt"), headers=TXT))
    assert ev.state is Tri.FOUND and ev.data["fields"]["contact"] == ["mailto:security@example.com", "https://example.com/report"]
    assert ev.data["expired"] is False and ev.data["expires"].startswith("2099")


def test_security_txt_404_is_absent():
    assert sec(response(404)).state is Tri.ABSENT


def test_html_page_served_as_security_txt_is_absent():
    assert sec(response(200, HOME_BODY, headers=HTML)).state is Tri.ABSENT
    assert sec(response(200, b"Hello", headers=TXT)).state is Tri.ABSENT  # text, but no Contact field


def test_security_txt_blocked_or_down_is_unknown_not_absent():
    for r in (response(403), response(503), response(429), response(error="timeout")):
        assert sec(r).state is Tri.UNKNOWN


def test_expired_security_txt_is_flagged():
    parsed = parse_security_txt("Contact: mailto:a@example.com\nExpires: 2020-01-01T00:00:00Z\n")
    assert parsed["expired"] is True


def test_trust_summary_never_cites_a_missing_check_as_absent_when_security_txt_alone_ran():
    result, _, found = run([(SEC_URL, response(404))], [home_page(links=[])])
    assert found["security_txt:example.com"].state is Tri.ABSENT and center(found).state is Tri.UNKNOWN


def test_an_error_page_with_links_is_not_the_homepage():
    for status in (403, 503):
        page = home_page()
        bad = Evidence(page.id, page.source, page.kind, page.subject, page.state, {**page.data, "status": status})
        http = FakeHttp()
        result = TrustPosture().run(make_ctx(http=http, evidence=[bad]))
        assert result.evidence[0].state is Tri.UNKNOWN and http.requested == []


def test_candidates_left_unchecked_by_the_cap_leave_the_center_unknown():
    links = [{"href": f"https://example.com/security/{i}", "text": "Security"} for i in range(8)]
    routes = [(f"https://example.com/security/{i}", response(404)) for i in range(8)] + [(SEC_URL, response(404))]
    result, http, found = run(routes, [home_page(links=links)])
    assert sum("/security/" in u and "robots" not in u for u in http.requested) == 5
    assert center(found).state is Tri.UNKNOWN and "3 more" in center(found).data["reason"]
