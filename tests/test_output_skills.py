"""Output skills: distinct descriptions, shared guards, and no forbidden content."""
import re
from pathlib import Path

PLUGIN = Path(__file__).resolve().parent.parent / "plugins" / "opportunity-recon"
OUTPUTS = ("precall-brief", "slide-deck", "outbound-drafts", "technical-detail", "scope-proposal", "buying-context")
FORBIDDEN = ("talk track", "discovery question", "disclaimer", "what to tell", "--depth", "--verbose", "lens")
STOP = {"the", "a", "an", "and", "or", "of", "for", "to", "in", "on", "with", "user", "asks", "use", "when", "from",
        "their", "its", "is", "by", "that", "each", "this", "run", "prospect", "research", "they", "it"}


def text(name):
    return (PLUGIN / "skills" / name / "SKILL.md").read_text()


def front(name):
    block = text(name).split("---\n", 2)[1]
    return dict(line.split(": ", 1) for line in block.strip().splitlines() if ": " in line)


def words(s):
    return {w for w in re.findall(r"[a-z]+", s.lower()) if w not in STOP and len(w) > 2}


def test_every_output_skill_has_a_matching_name_and_a_description():
    for name in OUTPUTS:
        fm = front(name)
        assert fm["name"] == name
        assert len(fm["description"]) > 60


def test_descriptions_are_distinct():
    descs = {n: front(n)["description"] for n in OUTPUTS}
    assert len(set(descs.values())) == len(OUTPUTS)
    for i, a in enumerate(OUTPUTS):
        for b in OUTPUTS[i + 1:]:
            wa, wb = words(descs[a]), words(descs[b])
            overlap = len(wa & wb) / min(len(wa), len(wb))
            assert overlap < 0.5, (a, b, overlap)


def test_each_description_names_its_own_trigger_words():
    triggers = {"precall-brief": "brief", "slide-deck": "deck", "outbound-drafts": "email",
                "technical-detail": "technical", "scope-proposal": "proposal", "buying-context": "why now"}
    for name, word in triggers.items():
        assert word in front(name)["description"].lower(), name


def test_each_skill_checks_the_profile_then_the_chats_run_and_runs_recon_if_missing():
    for name in OUTPUTS:
        t = text(name)
        assert "Opportunity Recon firm profile" in t and "setup skill" in t, name
        assert "bundle.json" in t and "snapshot.json" in t, name
        assert "recon skill" in t and "no run" in t.lower(), name
        assert "not_checked" in t, name
        assert "No placeholders" in t or "no placeholders" in t, name


def test_no_forbidden_content_or_engineer_options():
    for name in OUTPUTS:
        low = text(name).lower()
        assert not any(w in low for w in FORBIDDEN), name


def test_no_path_variables_and_no_stored_runs():
    for name in OUTPUTS:
        t = text(name)
        assert not any(v in t for v in ("CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA", "CLAUDE_SKILL_DIR")), name
        assert "recon-work" in t and "new chat has no run" in t.lower(), name


def test_deck_uses_a_brand_template_only_if_attached_and_never_stores_it():
    t = text("slide-deck")
    assert "attached" in t and "never saved" in t
    assert "reconbrief deck" in t and "--template" in t


def test_buying_context_requires_a_named_dated_source():
    t = text("buying-context")
    assert "named, dated source" in t and "left out" in t


def test_technical_detail_does_not_export_raw_data():
    assert "Do not export raw bundle data" in text("technical-detail")
