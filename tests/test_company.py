import pytest

from reconbrief.models import Evidence, Health, Tri
from reconbrief.sources.company import CompanyProfile, norm_name, same_site, trusted_names
from tests.helpers import FakeHttp, make_ctx, recorded, response

WD_SEARCH = "https://www.wikidata.org/w/api.php?action=wbsearchentities"
WD_LABELS = "https://www.wikidata.org/w/api.php?action=wbgetentities"
EDGAR_T = "https://www.sec.gov/files/company_tickers.json"
EDGAR_S = "https://data.sec.gov/submissions/CIK0001234567.json"
GLEIF = "https://api.gleif.org/api/v1/lei-records"


def routes(wikidata=True, edgar="acme", gleif="springfield"):
    r = []
    if wikidata:
        r += [(WD_SEARCH, recorded("wikidata_search_acme.json")),
              ("https://www.wikidata.org/wiki/Special:EntityData/Q111.json", recorded("wikidata_entity_q111.json")),
              ("https://www.wikidata.org/wiki/Special:EntityData/Q222.json", recorded("wikidata_entity_q222.json")),
              (WD_LABELS, recorded("wikidata_labels_q900.json"))]
    else:
        r += [(WD_SEARCH, b'{"search": []}')]
    r += [(EDGAR_T, recorded("edgar_tickers.json"))]
    if edgar:
        r += [(EDGAR_S, recorded("edgar_submissions_acme.json" if edgar == "acme" else "edgar_submissions_acme_nosite.json"))]
    r += [(GLEIF, recorded(f"gleif_acme_{gleif}.json"))]
    return r


def run(routes_, hint="Acme Corporation", domain="acme.com", evidence=()):
    http = FakeHttp(routes_)
    ctx = make_ctx(domain, http=http, evidence=evidence)
    ctx.company_hint = hint
    result = CompanyProfile().run(ctx)
    return result, {e.kind + ":" + e.subject: e for e in result.evidence}, http


def profile(found):
    return found["company_profile:acme.com"]


def test_wikidata_confirmed_by_domain_and_gleif_agrees_on_city():
    result, found, _ = run(routes())
    p = profile(found)
    assert p.state is Tri.FOUND and p.data["legal_name"] == "ACME CORP"  # EDGAR is confirmed by its website
    assert p.data["legal_name_source"] == "edgar" and p.data["cik"] == "1234567"
    assert p.data["lei"] == "5493001KJTIIGC8Y1R12" and p.data["hq_city"] == "Springfield"
    assert p.data["inception_year"] == "1998" and p.data["employees"] == "4200" and p.data["tickers"] == ["ACME"]
    assert p.data["confirmed_by"] == {"wikidata": ["domain"], "edgar": ["domain"], "gleif": ["city"]}
    assert result.health is Health.OK


def test_an_uncorroborated_gleif_hit_never_sets_legal_name():
    r = [(WD_SEARCH, b'{"search": []}'), (EDGAR_T, b"{}"), (GLEIF, recorded("gleif_acme_springfield.json"))]
    result, found, _ = run(r)
    p = profile(found)
    assert p.data["legal_name"] is None and p.data["legal_name_source"] is None and p.data["lei"] is None
    assert p.state is Tri.ABSENT
    lookup = found["company_lookup:gleif:acme"]
    assert lookup.state is Tri.FOUND and lookup.data["candidates"][0]["corroborated"] is False


def test_gleif_in_a_different_city_is_not_accepted_even_when_other_sources_are_confirmed():
    result, found, _ = run(routes(gleif="shelbyville"))
    p = profile(found)
    assert p.data["lei"] is None and "gleif" not in p.data["confirmed_by"]
    assert p.data["legal_name"] == "ACME CORP" and p.data["legal_name_source"] == "edgar"  # still from confirmed EDGAR


def test_wikidata_entity_for_a_different_website_is_rejected():
    result, found, _ = run(routes(), hint="Acme Corp")
    cands = {c["id"]: c for c in found["company_lookup:wikidata:acme"].data["candidates"]}
    assert cands["Q222"]["corroborated"] is False and cands["Q111"]["corroborated"] is True


def test_edgar_without_a_website_is_confirmed_by_city_only_against_a_confirmed_entity():
    result, found, _ = run(routes(edgar="nosite"))
    assert "edgar" not in profile(found).data["confirmed_by"]  # Shelbyville vs the confirmed Springfield
    r = [(WD_SEARCH, b'{"search": []}'), (EDGAR_T, recorded("edgar_tickers.json")),
         (EDGAR_S, recorded("edgar_submissions_acme_nosite.json")), (GLEIF, recorded("gleif_acme_shelbyville.json"))]
    result, found, _ = run(r)
    p = profile(found)
    assert p.state is Tri.ABSENT and p.data["legal_name"] is None  # no confirmed entity to compare cities with


def test_no_trusted_name_means_no_lookups():
    result, found, http = run(routes(), hint="")
    assert result.health is Health.SKIPPED and result.evidence == [] and http.requested == []


def test_trusted_names_come_only_from_hint_og_site_name_and_rdap():
    ev = [Evidence("p", "page_loader", "web_page", "acme.com", Tri.FOUND, {"og_site_name": "Acme Corp"}),
          Evidence("p2", "page_loader", "web_page", "blog.acme.com", Tri.FOUND, {"og_site_name": "Acme Blog"}),
          Evidence("h", "x", "ct_hostname", "acme-widgets.acme.com", Tri.FOUND),
          Evidence("r", "rdap", "rdap_domain", "acme.com", Tri.FOUND, {"registrant_org": "Acme Holdings LLC"}),
          Evidence("r2", "rdap", "rdap_domain", "acme.com", Tri.UNKNOWN, {})]
    ctx = make_ctx("acme.com", evidence=ev)
    ctx.company_hint = "ACME corporation"
    names = trusted_names(ctx)
    assert [(n["name"], n["source"]) for n in names] == [("ACME corporation", "user hint"),
                                                         ("Acme Holdings LLC", "RDAP registrant")]  # og:site_name repeats the hint, so it counts once
    ctx.company_hint = ""
    assert [n["name"] for n in trusted_names(ctx)] == ["Acme Corp", "Acme Holdings LLC"]  # blog.acme.com is not the homepage


def test_failed_lookups_leave_the_profile_unknown_not_absent():
    r = [(WD_SEARCH, response(503)), (EDGAR_T, response(error="timeout")), (GLEIF, response(500))]
    result, found, _ = run(r)
    assert profile(found).state is Tri.UNKNOWN and result.health is Health.FAILED
    assert all(e.state is Tri.UNKNOWN for e in found.values() if e.kind == "company_lookup")


def test_one_failed_source_is_partial_and_the_rest_still_count():
    r = routes()
    r[-1] = (GLEIF, response(503))
    result, found, _ = run(r)
    assert result.health is Health.PARTIAL and profile(found).state is Tri.FOUND
    assert found["company_lookup:gleif:acme"].state is Tri.UNKNOWN


@pytest.mark.parametrize("a, b", [("Acme Corp.", "ACME CORPORATION"), ("The Acme Company, Inc.", "acme"), ("Acme & Sons", "Acme and Sons")])
def test_name_normalisation(a, b):
    assert norm_name(a) == norm_name(b)


def test_different_names_do_not_match():
    assert norm_name("Acme Studios") != norm_name("Acme Corp")


def test_same_site():
    assert same_site("https://www.acme.com/", "acme.com") and same_site("acme.com", "acme.com")
    assert same_site("https://shop.acme.com", "acme.com") and not same_site("https://acme.com.evil.net", "acme.com")
    assert not same_site("", "acme.com")


def test_a_404_from_a_lookup_service_is_unknown_not_absent():
    r = [(WD_SEARCH, response(404)), (EDGAR_T, response(404)), (GLEIF, response(404))]
    result, found, _ = run(r)
    lookups = [e for e in found.values() if e.kind == "company_lookup"]
    assert len(lookups) == 3 and all(e.state is Tri.UNKNOWN for e in lookups)
    assert profile(found).state is Tri.UNKNOWN and result.health is Health.FAILED


def test_gleif_is_read_page_by_page_and_a_match_on_a_later_page_is_found():
    first = {"data": [{"attributes": {"lei": "X", "entity": {"legalName": {"name": "Acme Dental"}}}}],
             "meta": {"pagination": {"nextPage": 2}}}
    import json
    def pager(url):
        if "page%5Bnumber%5D=2" in url:
            return response(200, recorded("gleif_acme_springfield.json"))
        return response(200, json.dumps(first).encode())
    from reconbrief.sources.company import gleif_lookup
    state, cands, err = gleif_lookup(make_ctx("acme.com", http=FakeHttp([(GLEIF, pager)])), "Acme Corporation")
    assert state is Tri.FOUND and [c["id"] for c in cands] == ["5493001KJTIIGC8Y1R12"]


def test_unread_gleif_pages_make_a_miss_unknown_not_absent():
    import json
    endless = json.dumps({"data": [], "meta": {"pagination": {"nextPage": 2}}}).encode()
    from reconbrief.sources.company import MAX_PAGES, gleif_lookup
    http = FakeHttp([(GLEIF, response(200, endless))])
    state, cands, err = gleif_lookup(make_ctx("acme.com", http=http), "Acme Corporation")
    assert state is Tri.UNKNOWN and cands == [] and len(http.requested) == MAX_PAGES


def test_wikidata_search_follows_continue_and_gives_up_as_unknown():
    import json
    from reconbrief.sources.company import MAX_PAGES, wikidata_search
    def pages_of(url):
        body = {"search": [{"id": "Q1", "label": "Other Co"}], "search-continue": 50}
        if "continue=50" in url:
            body = {"search": [{"id": "Q111", "label": "Acme Corporation"}]}
        return response(200, json.dumps(body).encode())
    hits, err = wikidata_search(make_ctx("acme.com", http=FakeHttp([(WD_SEARCH, pages_of)])), "Acme Corporation")
    assert [h["id"] for h in hits] == ["Q111"]
    endless = json.dumps({"search": [], "search-continue": 50}).encode()
    http = FakeHttp([(WD_SEARCH, response(200, endless))])
    hits, err = wikidata_search(make_ctx("acme.com", http=http), "Acme Corporation")
    assert hits is None and len(http.requested) == MAX_PAGES
