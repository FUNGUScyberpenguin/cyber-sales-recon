import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

import reconbrief
from reconbrief.cli import app

ROOT = Path(__file__).resolve().parent.parent
runner = CliRunner()


def test_cli_help_runs():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "reconbrief" in result.output.lower()


def test_cli_version_matches_package():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert reconbrief.__version__ in result.output


def test_marketplace_points_at_plugin():
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    entry = market["plugins"][0]
    plugin_dir = ROOT / entry["source"]
    plugin = json.loads((plugin_dir / ".claude-plugin" / "plugin.json").read_text())
    assert entry["name"] == plugin["name"]
    assert market["owner"]["name"] == "FUNGUScyberpenguin"


SKILL_DIR = ROOT / "plugins" / "opportunity-recon" / "skills" / "python-check"


def test_throwaway_skill_uses_skill_dir_not_plugin_vars():
    text = (SKILL_DIR / "SKILL.md").read_text()
    assert text.startswith("---")
    assert "description:" in text
    assert "${CLAUDE_SKILL_DIR}/scripts/probe.py" in text
    assert "CLAUDE_PLUGIN_ROOT" not in text
    assert "CLAUDE_PLUGIN_DATA" not in text


def run_probe(home, cwd):
    return subprocess.run(
        [sys.executable, str(SKILL_DIR / "scripts" / "probe.py")],
        capture_output=True, text=True, timeout=60, cwd=cwd,
        env={
            "HOME": str(home), "TMPDIR": str(home), "RECON_PROBE_MNT": str(home / "mnt"),
            "PATH": os.environ.get("PATH", ""),
        },
    )


def test_probe_prints_python_version_and_script_location(tmp_path):
    result = run_probe(tmp_path, tmp_path)
    assert result.returncode == 0, result.stderr
    assert platform.python_version() in result.stdout
    assert str(SKILL_DIR / "scripts") in result.stdout


def test_probe_reports_marker_from_earlier_run(tmp_path):
    first = run_probe(tmp_path, tmp_path)
    assert "no earlier marker" in first.stdout
    second = run_probe(tmp_path, tmp_path)
    assert "1 earlier marker" in second.stdout


@pytest.mark.skipif(shutil.which("claude") is None, reason="claude CLI not installed")
def test_claude_plugin_validate_passes():
    for target in (ROOT, ROOT / "plugins" / "opportunity-recon"):
        result = subprocess.run(
            ["claude", "plugin", "validate", str(target)],
            capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
