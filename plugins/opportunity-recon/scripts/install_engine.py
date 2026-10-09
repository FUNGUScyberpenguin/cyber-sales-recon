"""Install the vendored reconbrief wheel by exact file path (never by package name)."""
import subprocess
import sys
from pathlib import Path

VENDOR = Path(__file__).resolve().parent.parent / "vendor"


def main() -> int:
    wheels = sorted(VENDOR.glob("reconbrief-*.whl"))
    if len(wheels) != 1:
        print(f"expected one wheel in {VENDOR}, found {len(wheels)}", file=sys.stderr)
        return 1
    return subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet", "--force-reinstall", str(wheels[0])]
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
