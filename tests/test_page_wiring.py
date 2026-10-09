import dns.exception

from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Pipeline
from reconbrief.sources import page_sources
from reconbrief.sources import vulns
from reconbrief.sources.vulns import Vulnerabilities
from tests.helpers import FakeHttp, make_ctx, recorded, response

HTML = [("Content-Type", "text/html"), ("Server", "Apache/2.4.49 (Unix)")]


def test_stages_feed_each_other_and_a_bad_source_does_not_stop_the_rest():
    sources = [Vulnerabilities(sleep=lambda s: None) if s.name == "vulnerabilities" else s for s in page_sources()]
    assert [s.stage for s in sources] == [3, 4, 4, 4]
    home = response(200, recorded("home_example.html"), headers=HTML, final_url="https://example.com/")
    trust_url = "https://example.com/trust"
    http = FakeHttp([
        ("https://example.com/robots.txt", response(404)),  # first match wins, so the specific URLs go first
        (trust_url, response(200, recorded("trust_center_example.html"), headers=HTML, final_url=trust_url)),
        ("https://example.com/.well-known/security.txt", response(404)), ("https://example.com/", home),
        ("https://www.cisa.gov/", response(503)),  # KEV down: partial, not fatal
        ("https://services.nvd.nist.gov/", response(200, recorded("nvd_empty.json"))),
        ("https://www.wikidata.org/", response(500)), ("https://www.sec.gov/", response(500)), ("https://api.gleif.org/", response(500)),
    ])
    rdap = Evidence("r", "rdap", "rdap_domain", "example.com", Tri.FOUND, {"registrant_org": "Example Corp"})
    result = Pipeline(sources).run(make_ctx(http=http, evidence=[rdap]))
    status = {h.source: h.status for h in result.health}
    assert status["page_loader"] is Health.OK and status["trust"] is Health.OK
    assert status["company"] is Health.FAILED and status["vulnerabilities"] is Health.PARTIAL
    kinds = {e.kind: e for e in result.evidence}
    assert kinds["trust_center"].state is Tri.FOUND  # stage 4 read stage 3's homepage
    assert kinds["vuln_lookup"].data["product"] == "Apache"
    assert kinds["company_profile"].state is Tri.UNKNOWN
    ids = [e.id for e in result.evidence]
    assert len(ids) == len(set(ids))
