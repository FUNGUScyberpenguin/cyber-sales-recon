"""Build the engine wheel into the recon skill's vendor/ folder.

Run from anywhere:  python scripts/build_wheel.py
Rerun whenever anything under reconbrief/ changes. A test fails if the wheel is stale.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "plugins" / "opportunity-recon" / "skills" / "recon" / "vendor"


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["uv", "build", "--wheel", "--out-dir", tmp, str(ROOT)], check=True)
        built = list(Path(tmp).glob("reconbrief-*.whl"))
        if len(built) != 1:
            print(f"expected one wheel, found {len(built)}", file=sys.stderr)
            return 1
        VENDOR.mkdir(parents=True, exist_ok=True)
        for old in VENDOR.glob("*.whl"):
            old.unlink()
        shutil.copy2(built[0], VENDOR / built[0].name)
    print(f"built {VENDOR / built[0].name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
