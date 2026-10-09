"""OWASP ZAP, used for passive scanning only.

The engine downloads one pinned ZAP release (checksum verified) into the data dir, starts it as a
local daemon, hands it a HAR of pages the engine already fetched, and reads the passive alerts.
ZAP never connects to a prospect: its own outbound traffic is pointed at a dead local port, and
the client below can only call the handful of API endpoints this module needs. Spider, active
scan, and request-sending endpoints are not in that list, so they cannot be called.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ZAP_VERSION = "2.17.0"
ZAP_URL = f"https://github.com/zaproxy/zaproxy/releases/download/v{ZAP_VERSION}/ZAP_{ZAP_VERSION}_Linux.tar.gz"
ZAP_SHA256 = "efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a"
MIN_JAVA = 17

# The only ZAP API calls the engine makes: (component, kind, name).
ALLOWED_CALLS = frozenset({
    ("core", "view", "version"),
    ("exim", "action", "importHar"),
    ("pscan", "view", "recordsToScan"),
    ("alert", "view", "alerts"),
    ("core", "action", "shutdown"),
})


class ZapUnavailable(Exception):
    """ZAP cannot be used here: no Java, no download, or it will not start. The source reports skipped."""


class ForbiddenCall(Exception):
    """Raised before any request is sent when code asks ZAP for something outside ALLOWED_CALLS."""


def default_data_dir() -> Path:
    """RECON_DATA_DIR, else the plugin data dir Claude Code provides, else ~/.reconbrief."""
    for var in ("RECON_DATA_DIR", "CLAUDE_PLUGIN_DATA"):
        if os.environ.get(var):
            return Path(os.environ[var])
    return Path.home() / ".reconbrief"


def java_major(java: str = "java") -> int | None:
    exe = shutil.which(java)
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "-version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r'version "(\d+)(?:\.(\d+))?', out.stdout + out.stderr)
    if not match:
        return None
    major = int(match.group(1))
    return int(match.group(2) or 0) if major == 1 else major  # "1.8.0" means Java 8


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def zap_home(data_dir: Path) -> Path:
    return data_dir / "zap" / ZAP_VERSION


def installed_script(data_dir: Path) -> Path | None:
    script = zap_home(data_dir) / "zap.sh"
    return script if script.is_file() else None


def download(url: str, dest: Path, timeout: float = 600.0) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "reconbrief"})
    with urllib.request.urlopen(request, timeout=timeout) as response, open(dest, "wb") as out:
        shutil.copyfileobj(response, out, 1 << 20)


def install(data_dir: Path, fetch=download, expected_sha256: str = ZAP_SHA256, url: str = ZAP_URL) -> Path:
    """Return the path to zap.sh, downloading and verifying the pinned release the first time."""
    script = installed_script(data_dir)
    if script:
        return script
    target = zap_home(data_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="zap-install-", dir=target.parent))
    try:
        archive = work / "zap.tar.gz"
        try:
            fetch(url, archive)
        except Exception as exc:
            raise ZapUnavailable(f"ZAP download failed ({type(exc).__name__}: {exc})") from exc
        actual = sha256_of(archive)
        if actual != expected_sha256:
            raise ZapUnavailable("ZAP download did not match the pinned checksum; not installed")
        extract = work / "extract"
        extract.mkdir()
        try:
            with tarfile.open(archive) as tar:
                tar.extractall(extract, filter="data")
        except (tarfile.TarError, OSError) as exc:
            raise ZapUnavailable(f"ZAP archive could not be unpacked ({exc})") from exc
        roots = [p for p in extract.iterdir() if p.is_dir()]
        if len(roots) != 1 or not (roots[0] / "zap.sh").is_file():
            raise ZapUnavailable("ZAP archive did not hold the expected folder")
        shutil.move(str(roots[0]), str(target))
        return target / "zap.sh"
    finally:
        shutil.rmtree(work, ignore_errors=True)


class ZapClient:
    """Calls the local ZAP API. Anything outside ALLOWED_CALLS is refused before it is sent."""

    def __init__(self, port: int, api_key: str, host: str = "127.0.0.1", timeout: float = 60.0) -> None:
        self.base = f"http://{host}:{port}"
        self.api_key = api_key
        self.timeout = timeout

    def call(self, component: str, kind: str, name: str, **params) -> dict:
        if (component, kind, name) not in ALLOWED_CALLS:
            raise ForbiddenCall(f"{component}/{kind}/{name} is not an allowed ZAP call")
        query = urllib.parse.urlencode({k: str(v) for k, v in params.items()})
        url = f"{self.base}/JSON/{component}/{kind}/{name}/" + (f"?{query}" if query else "")
        request = urllib.request.Request(url, headers={"X-ZAP-API-Key": self.api_key})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # the API is local; skip any proxy
        with opener.open(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def alerts(self, page: int = 5000) -> list[dict]:
        out: list[dict] = []
        while True:
            batch = self.call("alert", "view", "alerts", start=len(out), count=page).get("alerts", [])
            out.extend(batch)
            if len(batch) < page:
                return out


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class ZapDaemon:
    """ZAP running as a local daemon. Its own outbound requests go to a dead port, so it cannot reach a host."""

    script: Path
    port: int = 0
    api_key: str = ""
    process: subprocess.Popen | None = None
    home: Path | None = None

    def start(self, startup_timeout: float = 180.0) -> ZapClient:
        self.port = self.port or free_port()
        self.api_key = self.api_key or secrets.token_hex(16)
        self.home = Path(tempfile.mkdtemp(prefix="zap-session-"))
        command = [
            str(self.script), "-daemon", "-silent", "-host", "127.0.0.1", "-port", str(self.port),
            "-dir", str(self.home),
            "-config", f"api.key={self.api_key}",
            "-config", "api.addrs.addr.name=127.0.0.1", "-config", "api.addrs.addr.regex=false",
            # Dead-end proxy: if anything in ZAP tried to connect out, it would fail here.
            "-config", "connection.proxyChain.hostName=127.0.0.1",
            "-config", "connection.proxyChain.port=9",
            "-config", "connection.proxyChain.enabled=true",
            "-config", "start.checkForUpdates=false",
        ]
        try:
            self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            raise ZapUnavailable(f"ZAP would not start ({exc})") from exc
        client = ZapClient(self.port, self.api_key, timeout=30.0)
        deadline = time.monotonic() + startup_timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise ZapUnavailable(f"ZAP exited during startup (code {self.process.returncode})")
            try:
                client.call("core", "view", "version")
                client.timeout = 120.0
                return client
            except Exception:
                time.sleep(1.0)
        raise ZapUnavailable("ZAP did not start in time")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            try:
                ZapClient(self.port, self.api_key, timeout=10.0).call("core", "action", "shutdown")
                self.process.wait(timeout=20)
            except Exception:
                self.process.kill()
                self.process.wait()
        if self.home:
            shutil.rmtree(self.home, ignore_errors=True)
