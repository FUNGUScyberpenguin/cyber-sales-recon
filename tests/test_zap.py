"""Passive ZAP posture: recorded alerts, skipping, the pinned release, and the no-spider/no-active-scan rule."""
import hashlib
import io
import os
import json
import re
import tarfile
import threading
import shutil
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from reconbrief import zap
from reconbrief.har import build_har
from reconbrief.http import Fetch
from reconbrief.models import Health, Tier, Tri
from reconbrief.pipeline import Context, Pipeline
from reconbrief.rules_web_hygiene import web_hygiene_findings
from reconbrief.sources.zap_posture import COVERED_BY_ENGINE, ZapPassive
from tests.helpers import RECORDED, FakeHttp, ScriptedDns

ALERTS = json.loads((RECORDED / "zap_alerts_sample.json").read_text())
FORBIDDEN_WORDS = ("spider", "ascan", "ajaxspider", "accessurl", "sendrequest", "activescan")


def page(url="https://www.acme-test.example/"):
    return Fetch(url=url, final_url=url, status=200, body=b"<html></html>",
                 headers=[("Content-Type", "text/html"), ("Server", "Apache/2.4.41")])


def context(pages=(), tmp_path=None):
    c = Context("acme-test.example", ScriptedDns(), FakeHttp(), data_dir=tmp_path)
    c.captured.extend(pages)
    return c


class FakeZapServer:
    """A local stand-in for the ZAP API that serves recorded alerts and logs every path it is asked for."""

    def __init__(self, alerts=ALERTS, backlog=0):
        self.paths: list[str] = []
        self.alerts = alerts
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.paths.append(self.path)
                parts = urlsplit(self.path)
                name = parts.path.strip("/").split("/")
                query = parse_qs(parts.query)
                if name[:3] == ["JSON", "alert", "view"]:
                    start, count = int(query["start"][0]), int(query["count"][0])
                    body = {"alerts": outer.alerts[start:start + count]}
                elif name[-1] == "recordsToScan":
                    body = {"recordsToScan": str(backlog)}
                else:
                    body = {"Result": "OK"}
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


class FakeDaemon:
    def __init__(self, script, server):
        self.server, self.stopped = server, False

    def start(self):
        return zap.ZapClient(self.server.port, "k")

    def stop(self):
        self.stopped = True


def source_with(server, java=lambda: 21):
    return ZapPassive(installer=lambda d: Path("zap.sh"), daemon_factory=lambda script: FakeDaemon(script, server),
                      java_check=java)


# --- recorded HAR, recorded alerts -------------------------------------------------------

def test_recorded_har_is_valid_and_matches_what_the_engine_builds():
    har = json.loads((RECORDED / "zap_sample.har").read_text())
    entry = har["log"]["entries"][0]
    assert entry["request"]["url"] == "https://www.acme-test.example/"
    built = build_har([page()])["log"]["entries"][0]
    assert built["response"]["status"] == 200
    assert {"name": "Server", "value": "Apache/2.4.41"} in built["response"]["headers"]


def test_recorded_alerts_become_evidence_without_the_ones_the_engine_covers():
    server = FakeZapServer()
    try:
        result = source_with(server).run(context([page()]))
    finally:
        server.close()
    assert result.health is Health.OK
    alerts = [e for e in result.evidence if e.kind == "zap_alert"]
    found = {e.data["plugin_id"] for e in alerts}
    assert found == {"10010", "10011", "10054", "10017", "10027", "10040", "90003"}
    assert not found & set(COVERED_BY_ENGINE)  # no header, version, or cache-control duplicates
    assert all(e.state is Tri.FOUND and e.id.startswith("zap_passive:zap_alert:") for e in alerts)
    assert len({e.id for e in alerts}) == len(alerts)
    summary = next(e for e in result.evidence if e.kind == "zap_scan")
    assert summary.data["alerts_dropped"] == 7 and summary.data["zap_version"] == zap.ZAP_VERSION
    assert summary.data["pages_scanned"] == 1


def test_findings_cite_evidence_and_mixed_content_is_ask():
    server = FakeZapServer()
    try:
        result = source_with(server).run(context([page()]))
    finally:
        server.close()
    findings = web_hygiene_findings(result.evidence)
    ids = {e.id for e in result.evidence}
    assert findings and all(set(f.evidence_ids) <= ids for f in findings)
    tiers = {f.id: f.tier for f in findings}
    assert tiers["web_hygiene:10040"] is Tier.ASK
    assert tiers["web_hygiene:10010"] is Tier.BACKGROUND
    assert "web_hygiene:10035" not in tiers  # HSTS belongs to the engine's header rule


def test_scan_that_does_not_drain_is_partial(monkeypatch):
    monkeypatch.setattr("reconbrief.sources.zap_posture.SCAN_WAIT_SECONDS", 0)
    server = FakeZapServer(backlog=5)
    try:
        result = source_with(server).run(context([page()]))
    finally:
        server.close()
    assert result.health is Health.PARTIAL and "incomplete" in result.detail


# --- ZAP unavailable ---------------------------------------------------------------------

def test_no_java_is_skipped_and_run_completes(tmp_path):
    def unused(*a, **k):
        raise AssertionError("must not get this far")

    src = ZapPassive(installer=unused, daemon_factory=unused, java_check=lambda: None)
    result = Pipeline([src]).run(context([page()], tmp_path))
    health = result.health[0]
    assert health.status is Health.SKIPPED and "Java" in health.detail
    assert result.evidence == []


def test_old_java_is_skipped():
    src = ZapPassive(installer=None, daemon_factory=None, java_check=lambda: 11)
    assert src.run(context([page()])).health is Health.SKIPPED


def test_download_failure_is_skipped():
    def offline(data_dir):
        raise zap.ZapUnavailable("ZAP download failed (URLError: offline)")

    src = ZapPassive(installer=offline, java_check=lambda: 21)
    result = Pipeline([src]).run(context([page()]))
    assert result.health[0].status is Health.SKIPPED and "download failed" in result.health[0].detail


def test_zap_that_will_not_start_is_skipped():
    class Broken:
        def __init__(self, script):
            pass

        def start(self):
            raise zap.ZapUnavailable("ZAP did not start in time")

        def stop(self):
            pass

    src = ZapPassive(installer=lambda d: Path("zap.sh"), daemon_factory=Broken, java_check=lambda: 21)
    assert src.run(context([page()])).health is Health.SKIPPED


def test_no_pages_means_skipped_without_starting_anything():
    src = ZapPassive(installer=None, daemon_factory=None, java_check=None)
    assert src.run(context([])).health is Health.SKIPPED


# --- pinned release, checksum --------------------------------------------------------------

def test_release_is_pinned_by_exact_version_and_checksum():
    assert re.fullmatch(r"\d+\.\d+\.\d+", zap.ZAP_VERSION)
    assert zap.ZAP_URL.endswith(f"/download/v{zap.ZAP_VERSION}/ZAP_{zap.ZAP_VERSION}_Linux.tar.gz")
    assert re.fullmatch(r"[0-9a-f]{64}", zap.ZAP_SHA256)
    text = Path(zap.__file__).read_text()
    assert "git clone" not in text and "releases/latest" not in text


def make_archive(path: Path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"#!/bin/sh\n"
        info = tarfile.TarInfo(f"ZAP_{zap.ZAP_VERSION}/zap.sh")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    path.write_bytes(buf.getvalue())


def test_install_verifies_checksum_then_unpacks(tmp_path):
    src = tmp_path / "src.tar.gz"
    make_archive(src)
    good = hashlib.sha256(src.read_bytes()).hexdigest()
    script = zap.install(tmp_path / "data", fetch=lambda url, dest: shutil.copy(src, dest), expected_sha256=good)
    assert script == zap.zap_home(tmp_path / "data") / "zap.sh" and script.is_file()
    assert zap.install(tmp_path / "data", fetch=None) == script  # cached: no second download


def test_install_refuses_a_download_with_the_wrong_checksum(tmp_path):
    src = tmp_path / "src.tar.gz"
    make_archive(src)
    with pytest.raises(zap.ZapUnavailable, match="checksum"):
        zap.install(tmp_path / "data", fetch=lambda url, dest: shutil.copy(src, dest))
    assert not zap.zap_home(tmp_path / "data").exists()  # nothing was unpacked


# --- never a spider or an active scan; never a connection to a prospect ---------------------

def test_client_refuses_spider_active_scan_and_request_sending():
    client = zap.ZapClient(1, "k")  # port 1: a refused call must fail before any connection
    for call in [("spider", "action", "scan"), ("ascan", "action", "scan"), ("ajaxSpider", "action", "scan"),
                 ("core", "action", "sendRequest"), ("core", "action", "accessUrl"), ("exim", "action", "importUrls")]:
        with pytest.raises(zap.ForbiddenCall):
            client.call(*call)


def test_allowed_calls_hold_no_spider_or_active_scan():
    for component, kind, name in zap.ALLOWED_CALLS:
        assert not any(w in f"{component}{name}".lower() for w in FORBIDDEN_WORDS)


def test_a_run_makes_no_spider_or_active_scan_call():
    server = FakeZapServer()
    try:
        source_with(server).run(context([page()]))
    finally:
        server.close()
    assert server.paths, "the fake ZAP saw no calls"
    for path in server.paths:
        assert not any(w in path.lower() for w in FORBIDDEN_WORDS), path
    assert any("/exim/action/importHar/" in p for p in server.paths)


def test_zap_daemon_is_started_with_a_dead_end_proxy_and_local_api(monkeypatch, tmp_path):
    captured = {}

    def fake_popen(cmd, **kw):
        captured["cmd"] = cmd
        raise OSError("stop here")

    monkeypatch.setattr(zap.subprocess, "Popen", fake_popen)
    with pytest.raises(zap.ZapUnavailable):
        zap.ZapDaemon(Path("zap.sh")).start()
    cmd = captured["cmd"]
    assert "-daemon" in cmd and "-silent" in cmd
    assert cmd[cmd.index("-host") + 1] == "127.0.0.1"
    assert "connection.proxyChain.hostName=127.0.0.1" in cmd and "connection.proxyChain.enabled=true" in cmd


# --- live: real ZAP, only where it is already unpacked ------------------------------------

LIVE_DATA = os.environ.get("RECON_TEST_ZAP_DATA_DIR", "")  # a data dir that already holds zap/<version>


@pytest.mark.skipif(not (LIVE_DATA and zap.java_major()), reason="set RECON_TEST_ZAP_DATA_DIR to run against real ZAP")
def test_live_zap_passive_scan_of_the_recorded_page():
    har = json.loads((RECORDED / "zap_sample.har").read_text())
    entry = har["log"]["entries"][0]
    headers = [(h["name"], h["value"]) for h in entry["response"]["headers"]]
    f = Fetch(url=entry["request"]["url"], final_url=entry["request"]["url"], status=200, headers=headers,
              body=entry["response"]["content"]["text"].encode())
    result = ZapPassive().run(context([f], Path(LIVE_DATA)))
    assert result.health is Health.OK
    found = {e.data["plugin_id"] for e in result.evidence if e.kind == "zap_alert"}
    assert {"10010", "10011", "10040"} <= found
