"""Passive web-hygiene scan with OWASP ZAP.

Runs after the page loader. The pages the loader already fetched go to ZAP as a HAR; ZAP scans them
passively and makes no connection to the prospect. If Java or the ZAP download is missing, the
source reports "skipped" and the run completes.
"""
from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from reconbrief import zap
from reconbrief.har import write_har
from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.common import make_evidence

# ZAP passive rules the engine's own header, version, and certificate rules already cover.
# Their alerts are dropped so nothing is reported twice.
COVERED_BY_ENGINE = {
    "10020": "anti-clickjacking header",
    "10021": "X-Content-Type-Options header",
    "10035": "Strict-Transport-Security header",
    "10036": "Server version header",
    "10037": "X-Powered-By version header",
    "10038": "Content-Security-Policy header missing",
    "10063": "Permissions-Policy header",
    "10015": "cache-control directives",
}
SCAN_WAIT_SECONDS = 120
EVIDENCE_CHARS = 200


def _alert_evidence(source: str, alert: dict) -> Evidence:
    host = (urlsplit(alert.get("url", "")).hostname or "").lower()
    plugin = str(alert.get("pluginId", ""))
    param = alert.get("param", "") or ""
    subject = f"{host}/{plugin}" + (f"/{param}" if param else "")
    return make_evidence(
        source, "zap_alert", subject, Tri.FOUND, host=host, plugin_id=plugin, alert=alert.get("alert", ""),
        risk=alert.get("risk", ""), confidence=alert.get("confidence", ""), url=alert.get("url", ""),
        param=param, matched=(alert.get("evidence", "") or "")[:EVIDENCE_CHARS], cwe=str(alert.get("cweid", "")),
    )


class ZapPassive:
    name = "zap_passive"
    stage = 5

    def __init__(self, installer=zap.install, daemon_factory=zap.ZapDaemon, java_check=zap.java_major) -> None:
        self.installer = installer
        self.daemon_factory = daemon_factory
        self.java_check = java_check

    def run(self, ctx: Context) -> SourceResult:
        pages = [f for f in ctx.captured if f.ok]
        if not pages:
            return SourceResult(Health.SKIPPED, [], "no pages were loaded, so nothing to scan")
        java = self.java_check()
        if java is None or java < zap.MIN_JAVA:
            return SourceResult(Health.SKIPPED, [], f"Java {zap.MIN_JAVA}+ not available, web-hygiene scan not run")
        data_dir = ctx.data_dir or zap.default_data_dir()
        try:
            script = self.installer(data_dir)
        except zap.ZapUnavailable as exc:
            return SourceResult(Health.SKIPPED, [], str(exc))
        except OSError as exc:
            return SourceResult(Health.SKIPPED, [], f"ZAP could not be installed ({exc})")
        work = Path(tempfile.mkdtemp(prefix="zap-har-"))
        daemon = self.daemon_factory(script)
        try:
            try:
                client = daemon.start()
            except zap.ZapUnavailable as exc:
                return SourceResult(Health.SKIPPED, [], str(exc))
            har_path = work / "pages.har"
            count = write_har(pages, har_path)
            client.call("exim", "action", "importHar", filePath=str(har_path))
            drained = self._wait_for_scan(client)
            alerts = client.alerts()
        finally:
            daemon.stop()
            shutil.rmtree(work, ignore_errors=True)
        evidence, dropped = self._evidence(alerts)
        summary = make_evidence(self.name, "zap_scan", ctx.domain, Tri.FOUND, zap_version=zap.ZAP_VERSION,
                                pages_scanned=count, alerts_kept=len(evidence), alerts_dropped=dropped,
                                scan_finished=drained)
        detail = f"{count} pages scanned passively"
        if not drained:
            detail += "; scan did not finish in time, alerts may be incomplete"
        return SourceResult(Health.OK if drained else Health.PARTIAL, [summary] + evidence, detail)

    def _wait_for_scan(self, client: zap.ZapClient) -> bool:
        deadline = time.monotonic() + SCAN_WAIT_SECONDS
        while time.monotonic() < deadline:
            if int(client.call("pscan", "view", "recordsToScan").get("recordsToScan", "0")) == 0:
                return True
            time.sleep(1.0)
        return False

    def _evidence(self, alerts: list[dict]) -> tuple[list[Evidence], int]:
        kept: dict[str, Evidence] = {}
        dropped = 0
        for alert in alerts:
            if str(alert.get("pluginId", "")) in COVERED_BY_ENGINE:
                dropped += 1
                continue
            ev = _alert_evidence(self.name, alert)
            kept.setdefault(ev.id, ev)  # one record per host, rule, and parameter
        return list(kept.values()), dropped
