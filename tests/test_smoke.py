import json
import shutil
import subprocess
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


def test_throwaway_skill_exists():
    skill = ROOT / "plugins" / "opportunity-recon" / "skills" / "python-check" / "SKILL.md"
    text = skill.read_text()
    assert text.startswith("---")
    assert "description:" in text


@pytest.mark.skipif(shutil.which("claude") is None, reason="claude CLI not installed")
def test_claude_plugin_validate_passes():
    for target in (ROOT, ROOT / "plugins" / "opportunity-recon"):
        result = subprocess.run(
            ["claude", "plugin", "validate", str(target)],
            capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
