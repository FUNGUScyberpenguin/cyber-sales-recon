from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context, Pipeline, SourceResult
from reconbrief.http import AddressGuard, HttpClient
from reconbrief.resolver import DnsResolver


def ctx():
    r = DnsResolver(nameservers=["192.0.2.53"])
    return Context("example.com", r, HttpClient(AddressGuard(r)))


class Src:
    def __init__(self, name, stage, fn):
        self.name, self.stage, self.fn = name, stage, fn

    def run(self, c):
        return self.fn(c)


def ev(i):
    return Evidence(i, "s", "k", "example.com", Tri.FOUND)


def test_records_health_per_source_and_survives_a_crash():
    def boom(c):
        raise RuntimeError("nope")

    sources = [
        Src("good", 1, lambda c: SourceResult(Health.OK, [ev("E1")])),
        Src("bad", 1, boom),
        Src("part", 1, lambda c: SourceResult(Health.PARTIAL, [ev("E2")], "2 of 3 lookups failed")),
        Src("skip", 1, lambda c: SourceResult(Health.SKIPPED, [], "needs a key")),
    ]
    result = Pipeline(sources).run(ctx())
    status = {h.source: h.status for h in result.health}
    assert status == {"good": Health.OK, "bad": Health.FAILED, "part": Health.PARTIAL, "skip": Health.SKIPPED}
    assert {e.id for e in result.evidence} == {"E1", "E2"}
    assert {h.source for h in result.failed()} == {"bad", "part"}
    assert "RuntimeError: nope" in next(h.detail for h in result.health if h.source == "bad")


def test_later_stages_see_earlier_evidence():
    seen = {}

    def late(c):
        seen["ids"] = [e.id for e in c.evidence]
        return SourceResult()

    sources = [Src("late", 2, late), Src("early", 1, lambda c: SourceResult(Health.OK, [ev("E1")]))]
    Pipeline(sources).run(ctx())
    assert seen["ids"] == ["E1"]
