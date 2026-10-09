import dataclasses

import pytest

from reconbrief.models import LENSES, Evidence, Finding, SourceHealth, Tier, Tri

FORBIDDEN = ("talk", "question", "discovery", "disclaimer", "script", "pitch")


def test_models_have_no_talk_track_or_question_fields():
    for cls in (Evidence, Finding, SourceHealth):
        for f in dataclasses.fields(cls):
            assert not any(word in f.name.lower() for word in FORBIDDEN), f.name


def test_finding_must_cite_evidence():
    with pytest.raises(ValueError):
        Finding("F1", "rule", "t", "d", Tier.ASK, ())


def test_finding_rejects_unknown_lens():
    with pytest.raises(ValueError):
        Finding("F1", "rule", "t", "d", Tier.ASK, ("E1",), ("made-up",))


def test_finding_accepts_the_six_lenses():
    assert len(LENSES) == 6
    f = Finding("F1", "rule", "t", "d", Tier.ASK, ("E1",), LENSES)
    assert f.to_dict()["evidence_ids"] == ["E1"]


def test_tri_has_exactly_three_states():
    assert {t.value for t in Tri} == {"found", "absent", "unknown"}
