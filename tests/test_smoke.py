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


def test_throwaway_skill_finds_script_without_path_variables():
    # Chat and Cowork leave every path variable unset, so the skill must locate its own script.
    text = (SKILL_DIR / "SKILL.md").read_text()
    assert text.startswith("---")
    assert "description:" in text
    assert "scripts/probe.py" in text
    assert "find " in text
    for var in ("CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA", "CLAUDE_SKILL_DIR"):
        assert var not in text


def run_probe(home, cwd, extra_env=None):
    return subprocess.run(
        [sys.executable, str(SKILL_DIR / "scripts" / "probe.py")],
        capture_output=True, text=True, timeout=60, cwd=cwd,
        env={
            "HOME": str(home), "TMPDIR": str(home), "RECON_PROBE_MNT": str(home / "mnt"),
            "RECON_PROBE_EXTRA_ROOTS": "",
            "PATH": os.environ.get("PATH", ""),
            **(extra_env or {}),
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


def test_probe_finds_project_test_file_and_reports_writability(tmp_path):
    project = tmp_path / "mnt" / "project-files" / "sales"
    project.mkdir(parents=True)
    (project / "probe-test.txt").write_text("hello")
    (project / "brand.pptx").write_bytes(b"x")
    result = run_probe(tmp_path, tmp_path)
    assert result.returncode == 0, result.stderr
    assert f"found {project / 'probe-test.txt'}" in result.stdout
    assert f"found {project / 'brand.pptx'}" in result.stdout
    assert "folder writable: yes" in result.stdout


def test_probe_reports_read_only_folder(tmp_path):
    project = tmp_path / "mnt" / "proj"
    project.mkdir(parents=True)
    (project / "probe-test.txt").write_text("hello")
    project.chmod(0o555)
    try:
        if os.access(project, os.W_OK):
            pytest.skip("running as a user that ignores permissions")
        result = run_probe(tmp_path, tmp_path)
        assert "folder writable: no" in result.stdout
    finally:
        project.chmod(0o755)


def test_probe_lists_mnt_layout_and_env_names_but_never_values(tmp_path):
    (tmp_path / "mnt" / "user-data" / "uploads").mkdir(parents=True)
    result = run_probe(tmp_path, tmp_path, {"CLAUDE_FAKE_TOKEN": "supersecretvalue"})
    assert "user-data/uploads" in result.stdout
    assert "CLAUDE_FAKE_TOKEN" in result.stdout
    assert "supersecretvalue" not in result.stdout


def test_probe_prints_mount_section(tmp_path):
    result = run_probe(tmp_path, tmp_path)
    assert "Mounts:" in result.stdout


def test_probe_survives_broken_symlink_match(tmp_path):
    folder = tmp_path / "mnt" / "proj"
    folder.mkdir(parents=True)
    (folder / "probe-test-link.txt").symlink_to(tmp_path / "does-not-exist")
    result = run_probe(tmp_path, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Markers:" in result.stdout
