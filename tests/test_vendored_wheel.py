"""The plugin ships the engine as a wheel. These tests fail if it no longer matches reconbrief/."""
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "plugins" / "opportunity-recon" / "vendor"
SOURCE = ROOT / "reconbrief"


def source_files():
    return {f"reconbrief/{p.relative_to(SOURCE).as_posix()}": p
            for p in SOURCE.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}


def test_exactly_one_vendored_wheel():
    assert len(list(VENDOR.glob("reconbrief-*.whl"))) == 1


def test_vendored_wheel_is_not_stale():
    wheel = next(VENDOR.glob("reconbrief-*.whl"))
    with zipfile.ZipFile(wheel) as z:
        packaged = {n: z.read(n) for n in z.namelist() if n.startswith("reconbrief/")}
    expected = source_files()
    assert set(packaged) == set(expected), "file list differs: run python scripts/build_wheel.py"
    stale = [n for n, p in expected.items() if p.read_bytes() != packaged[n]]
    assert not stale, f"stale in wheel: {stale}. Run python scripts/build_wheel.py"


def test_vendored_wheel_metadata_matches_pyproject():
    import tomllib
    wheel = next(VENDOR.glob("reconbrief-*.whl"))
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    with zipfile.ZipFile(wheel) as z:
        meta = z.read(next(n for n in z.namelist() if n.endswith("METADATA"))).decode()
    assert f"Version: {pyproject['project']['version']}" in meta
    for dep in pyproject["project"]["dependencies"]:
        assert f"Requires-Dist: {dep}" in meta, f"{dep} missing from wheel metadata"


def test_install_script_installs_by_file_path_only():
    text = (ROOT / "plugins" / "opportunity-recon" / "scripts" / "install_engine.py").read_text()
    assert 'str(wheels[0])' in text
    assert "install reconbrief" not in text and '"reconbrief"' not in text
