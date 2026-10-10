"""Setup and recon skills: where they keep things, how they find their files, and what they never do."""
import json
import re
from pathlib import Path

from reconbrief.recommend import load_offerings

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "opportunity-recon"
SETUP = (PLUGIN / "skills" / "setup" / "SKILL.md").read_text()
RECON = (PLUGIN / "skills" / "recon" / "SKILL.md").read_text()
PATH_VARS = ("CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA", "CLAUDE_SKILL_DIR")
FORBIDDEN = ("talk track", "discovery question", "disclaimer", "what to tell")


def frontmatter(text):
    assert text.startswith("---\n")
    block = text.split("---\n", 2)[1]
    return dict(line.split(": ", 1) for line in block.strip().splitlines() if ": " in line)


def test_both_skills_have_names_and_descriptions():
    for text, name in ((SETUP, "setup"), (RECON, "recon")):
        fm = frontmatter(text)
        assert fm["name"] == name
        assert len(fm["description"]) > 40


def test_no_path_variables_anywhere_in_the_plugin():
    for path in PLUGIN.rglob("*"):
        if path.is_file() and path.suffix in (".md", ".py", ".json"):
            text = path.read_text()
            assert not any(v in text for v in PATH_VARS) or "probe" in path.name or "python-check" in str(path), path


def test_recon_finds_its_own_folder_and_installs_the_wheel_from_it():
    assert "find " in RECON
    assert "skills/recon/SKILL.md" in RECON
    assert "scripts/install_engine.py" in RECON
    assert (PLUGIN / "skills" / "recon" / "scripts" / "install_engine.py").exists()
    assert list((PLUGIN / "skills" / "recon" / "vendor").glob("reconbrief-*.whl"))
    assert not (PLUGIN / "vendor").exists()


def test_profile_lives_in_memory_with_a_project_instructions_backup():
    low = SETUP.lower()
    assert "project memory" in low and "general memory" in low
    assert "project instructions" in low
    assert "Opportunity Recon firm profile" in SETUP and "Opportunity Recon firm profile" in RECON


def test_every_skill_runs_setup_when_the_profile_is_missing():
    assert re.search(r"missing.*setup|setup.*missing", RECON, re.I | re.S)
    assert "original request" in RECON.lower()


def test_no_run_storage_and_the_brand_template_comes_from_the_chat():
    for text in (SETUP, RECON):
        assert "saved run" not in text.lower().replace("no saved run", "")
    assert "new chat" in RECON.lower()
    assert "attach" in SETUP.lower() and ".pptx" in SETUP


def test_recon_runs_preflight_then_the_engine_and_asks_what_next():
    assert RECON.index("reconbrief preflight") < RECON.index("reconbrief run")
    assert "which hosts are blocked" in RECON and "exits with 3" in RECON
    assert "not checked" in RECON
    for output in ("pre-call brief", "slide deck", "outbound drafts", "technical detail",
                   "scope and proposal outline", "buying context"):
        assert output in RECON.lower()
    assert "other questions" in RECON and "more research" in RECON


def test_recon_has_no_engineer_options_or_talk_tracks():
    for text in (SETUP, RECON):
        low = text.lower()
        assert not any(w in low for w in FORBIDDEN)
    assert "--depth" not in RECON and "--verbose" not in RECON
    assert "never show" in SETUP.lower() and "lens" in SETUP.lower()  # lenses are mapped silently


def test_profile_json_example_loads_with_the_engine(tmp_path):
    block = re.search(r"```json\n(.*?)```", RECON, re.S).group(1)
    path = tmp_path / "profile.json"
    path.write_text(block)
    offerings = load_offerings(path)
    assert offerings and all(o.lenses for o in offerings)
    assert json.loads(block)["offerings"]
