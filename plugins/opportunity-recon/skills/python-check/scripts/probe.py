import fnmatch
import glob
import os
import platform
import sys
import tempfile
import time
from pathlib import Path

MARKER = "recon-probe-marker.txt"
PATTERNS = ("probe-test*", "*.pptx")
SKIP_DIRS = {"node_modules", ".git", ".venv", "__pycache__", "proc", "sys"}
MAX_DEPTH = 6
MAX_DIRS = 3000

MNT = os.environ.get("RECON_PROBE_MNT", "/mnt")
EXTRA_ROOTS = [r for r in os.environ.get("RECON_PROBE_EXTRA_ROOTS", "/workspace:/data").split(":") if r]
MNT_SKIP = (f"{MNT}/skills", f"{MNT}/sandboxing")
SYSTEM_FS = {
    "proc", "sysfs", "cgroup", "cgroup2", "devpts", "devtmpfs", "mqueue", "securityfs",
    "tracefs", "debugfs", "pstore", "bpf", "configfs", "fusectl", "binfmt_misc", "autofs",
}


def can_write(folder):
    probe = folder / f".recon-write-test-{os.getpid()}"
    try:
        probe.write_text("x")
        probe.unlink()
        return True
    except OSError:
        return False


def show_layout():
    print("\nLayout of", MNT)
    for first in sorted(glob.glob(f"{MNT}/*")):
        if first.startswith(MNT_SKIP):
            continue
        print(" ", first)
        if os.path.isdir(first):
            for second in sorted(glob.glob(f"{first}/*"))[:40]:
                print("   ", second)


def show_mounts():
    print("\nMounts:")
    try:
        lines = Path("/proc/mounts").read_text().splitlines()
    except OSError:
        print("  /proc/mounts not readable")
        return
    shown = 0
    for line in lines:
        parts = line.split()
        if len(parts) < 3 or parts[2] in SYSTEM_FS or parts[1].startswith(("/proc", "/sys", "/dev")):
            continue
        print(f"  {parts[1]} ({parts[2]})")
        shown += 1
    if not shown:
        print("  none besides system mounts")


def show_env_names():
    names = sorted(k for k in os.environ if any(w in k.upper() for w in ("CLAUDE", "COWORK", "PROJECT")))
    print("\nEnvironment variable names (values hidden):", ", ".join(names) or "none")


def file_size(path):
    try:
        return f"{path.stat().st_size} bytes"
    except OSError:
        return "size unknown"


def search_files(roots):
    print("\nSearching for", ", ".join(PATTERNS))
    found = set()
    visited = 0
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            visited += 1
            if visited > MAX_DIRS:
                print("  stopped searching after", MAX_DIRS, "folders")
                print("  nothing found" if not found else "")
                return
            dirnames[:] = [
                d for d in dirnames
                if d not in SKIP_DIRS and not os.path.join(dirpath, d).startswith(MNT_SKIP)
            ]
            if len(Path(dirpath).parts) - base_depth >= MAX_DEPTH:
                dirnames[:] = []
            for name in filenames:
                if any(fnmatch.fnmatch(name.lower(), p) for p in PATTERNS):
                    path = Path(dirpath) / name
                    if path in found or ".claude/plugins" in str(path):
                        continue
                    found.add(path)
                    print(f"  found {path} ({file_size(path)})")
                    print(f"    folder writable: {'yes' if can_write(path.parent) else 'no'}")
    if not found:
        print("  nothing found")


def write_markers():
    print("\nMarkers:")
    candidates = [Path.home(), Path.cwd(), Path(tempfile.gettempdir())]
    candidates += [
        Path(p) for p in sorted(glob.glob(f"{MNT}/*")) + sorted(glob.glob(f"{MNT}/*/*"))
        if not p.startswith(MNT_SKIP)
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
            print(f"  {folder}: not writable ({e.strerror})")
            continue
        if earlier:
            print(f"  {folder}: wrote marker, {len(earlier)} earlier marker(s), first at {earlier[0]}")
        else:
            print(f"  {folder}: wrote marker, no earlier marker")


print(f"Python {platform.python_version()} on {platform.machine()} ({platform.system()})")
print(f"Script folder: {Path(__file__).resolve().parent}")
print(f"Working folder: {os.getcwd()}")
show_env_names()
show_mounts()
show_layout()
search_files([MNT, Path.home(), Path.cwd(), *EXTRA_ROOTS])
write_markers()
sys.exit(0)
