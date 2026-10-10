import json

import pytest

from reconbrief.models import Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.preflight import looks_blocked, run_preflight
from reconbrief.recommend import Offering, ProfileError, load_offerings, recommend
from reconbrief.run import BadDomain, clean_domain, run_recon
from reconbrief.sources.common import make_evidence
from tests.helpers import FakeHttp, ScriptedDns, response
from tests.rule_helpers import D, findings, host_dns, page, txt


class Stub:
    def __init__(self, name, stage, evidence=(), health=Health.OK, detail="", boom=False):
        self.name, self.stage, self._ev, self._h, self._d, self._boom = name, stage, list(evidence), health, detail, boom

    def run(self, ctx):
        if self._boom:
            raise RuntimeError("source crashed")
        return SourceResult(self._h, self._ev, self._d)


def ctx_for(http=None):
    return Context(D, ScriptedDns(), http or FakeHttp())


HOSTS = {"a.test": "https://a.test/", "b.test": "https://b.test/"}
OK_HTTP = FakeHttp([("https://", response(200, b"ok"))])


def test_clean_domain():
    assert clean_domain("https://WWW.Acme.com/path?x=1") == "acme.com"
    assert clean_domain("user@acme.com:8443") == "acme.com"
    for bad in ("not a domain", "localhost", ""):
        with pytest.raises(BadDomain):
            clean_domain(bad)


def test_run_writes_bundle_and_snapshot(tmp_path):
    ev = [txt("spf", D, Tri.ABSENT), host_dns("staging.acme.com"), page("www.acme.com", title="Sign in", has_password_form=True),
          make_evidence("rdap", "rdap_domain", D, Tri.UNKNOWN, error="timeout")]
    sources = [Stub("dns_records", 1, ev), Stub("zap_passive", 5, [], Health.SKIPPED, "Java not available"),
               Stub("vulnerabilities", 4, boom=True)]
    offerings = [Offering("Web app test", ("web-app-api",)), Offering("Red team", ("red-team",))]
    out = run_recon("https://www.acme.com", tmp_path, "Acme", offerings, ctx=ctx_for(OK_HTTP), sources=sources, preflight_hosts=HOSTS)
    bundle = json.loads((tmp_path / "bundle.json").read_text())
    snap = json.loads((tmp_path / "snapshot.json").read_text())
    assert bundle["domain"] == "acme.com" and bundle["company_hint"] == "Acme"
    assert {f["id"] for f in bundle["findings"]} >= {"non_production_hosts:strong", "login_portals:all"}
    assert all(f["evidence_ids"] for f in bundle["findings"])
    ids = {e["id"] for e in bundle["evidence"]}
    assert all(set(f["evidence_ids"]) <= ids for f in bundle["findings"])
    assert snap["counts"]["live_hosts"] == 1 and snap["counts"]["findings"] == len(bundle["findings"])
    assert snap["top_findings"][0]["tier"] in ("lead", "ask", "background")
    # Failed and skipped sources show up as "not checked", with the lookups that came back unknown.
    nc = {r["source"]: r for r in snap["not_checked"]}
    assert nc["vulnerabilities"]["status"] == "failed" and "source crashed" in nc["vulnerabilities"]["detail"]
    assert nc["zap_passive"]["status"] == "skipped"
    assert snap["recommendation"]["offering"] in {"Web app test", "Red team"}
    assert out.snapshot == snap


def test_unknown_lookups_show_as_not_checked(tmp_path):
    unknown = make_evidence("rdap", "rdap_domain", D, Tri.UNKNOWN, error="timeout")
    out = run_recon("acme.com", tmp_path, ctx=ctx_for(OK_HTTP), preflight_hosts=HOSTS,
                    sources=[Stub("rdap", 1, [unknown], Health.PARTIAL, "1 lookup not checked")])
    row = out.snapshot["not_checked"][0]
    assert row["source"] == "rdap" and row["unknown_checks"] == 1
    assert not [f for f in out.bundle["findings"] if f["rule"] == "domain_registration"]


def test_no_profile_means_no_recommendation(tmp_path):
    out = run_recon("acme.com", tmp_path, ctx=ctx_for(OK_HTTP), sources=[Stub("dns_records", 1, [txt("spf", D, Tri.ABSENT)])],
                    preflight_hosts=HOSTS)
    assert out.snapshot["recommendation"] is None


def test_blocked_preflight_stops_the_run_and_names_hosts(tmp_path):
    http = FakeHttp([("https://a.test", response(200, b"ok")), ("https://b.test", response(403, b"denied"))])
    stub = Stub("dns_records", 1, [txt("spf", D, Tri.ABSENT)])
    (tmp_path / "bundle.json").write_text("{}")
    out = run_recon("acme.com", tmp_path, ctx=ctx_for(http), sources=[stub], preflight_hosts=HOSTS)
    assert out.blocked is not None and out.blocked.blocked == ["b.test"]
    assert "b.test" in out.snapshot["message"]
    assert not (tmp_path / "bundle.json").exists()  # including one left over from an earlier run
    assert json.loads((tmp_path / "snapshot.json").read_text())["blocked"] is True


def test_preflight_blocked_and_unreachable():
    http = FakeHttp([("https://a.test", response(407)), ("https://b.test", response(200, headers=[("Via", "1.1 squid")]))])
    result = run_preflight(http, HOSTS)
    assert result.blocked == ["a.test", "b.test"] and not result.ok
    http = FakeHttp([("https://a.test", response(200))])  # b.test: connect_failed
    result = run_preflight(http, HOSTS)
    assert result.unreachable == ["b.test"] and not result.blocked


def test_preflight_ok_and_looks_blocked():
    assert run_preflight(OK_HTTP, HOSTS).ok
    assert looks_blocked(403, []) and looks_blocked(407, []) and looks_blocked(200, [("Proxy-Authenticate", "Basic")])
    assert not looks_blocked(200, [("Via", "1.1 cloudfront"), ("Server", "nginx")])
    assert not looks_blocked(404, [])


def test_recommendation_uses_only_the_users_offerings():
    f = list(findings([host_dns("staging.acme.com"), txt("spf", D, Tri.ABSENT)]).values())
    rec = recommend([Offering("Red team", ("red-team",)), Offering("Web app test", ("web-app-api",))], f)
    assert rec["offering"] == "Web app test" and rec["finding_ids"]  # the non-production hosts (ask) outweigh the missing SPF (background)
    assert recommend([Offering("AI red team", ("ai-red-teaming",))], f) is None
    assert recommend([], f) is None


def test_load_offerings(tmp_path):
    p = tmp_path / "profile.json"
    p.write_text(json.dumps({"firm_name": "X", "offerings": [{"name": "Red team", "lenses": ["red-team"]}]}))
    assert load_offerings(p) == [Offering("Red team", ("red-team",))]
    p.write_text(json.dumps({"offerings": [{"name": "Bad", "lenses": ["magic"]}]}))
    with pytest.raises(ProfileError):
        load_offerings(p)
    p.write_text("{}")
    with pytest.raises(ProfileError):
        load_offerings(p)
