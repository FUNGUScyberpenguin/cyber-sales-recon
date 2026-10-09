import glob
import os
import platform
import sys
import tempfile
import time
from pathlib import Path

MARKER = "recon-probe-marker.txt"

print(f"Python {platform.python_version()} on {platform.machine()} ({platform.system()})")
print(f"Script folder: {Path(__file__).resolve().parent}")
print(f"Working folder: {os.getcwd()}")

candidates = [Path.home(), Path.cwd(), Path(tempfile.gettempdir())]
MNT = os.environ.get("RECON_PROBE_MNT", "/mnt")
SKIP = (f"{MNT}/skills", f"{MNT}/sandboxing")
candidates += [
    Path(p) for p in sorted(glob.glob(f"{MNT}/*")) + sorted(glob.glob(f"{MNT}/*/*"))
    if not p.startswith(SKIP)
]

seen = set()
for folder in candidates:
    folder = folder.resolve()
    if folder in seen or not folder.is_dir():
        continue
    seen.add(folder)
    marker = folder / MARKER
    try:
        earlier = marker.read_text().splitlines() if marker.exists() else []
        with marker.open("a") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
    except OSError as e:
        print(f"{folder}: not writable ({e.strerror})")
        continue
    if earlier:
        print(f"{folder}: wrote marker, {len(earlier)} earlier marker(s), first at {earlier[0]}")
    else:
        print(f"{folder}: wrote marker, no earlier marker")
sys.exit(0)
