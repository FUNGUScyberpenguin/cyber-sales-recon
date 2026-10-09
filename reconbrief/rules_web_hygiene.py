"""Turn ZAP passive alerts into findings. Nothing here sends a request."""
from __future__ import annotations

from reconbrief.models import Evidence, Finding, Tier

COOKIE_RULES = {"10010", "10011", "10054"}  # no HttpOnly, no Secure, no SameSite
MIXED_CONTENT_RULES = {"10040"}  # HTTPS page loading HTTP content
FINDING_LENSES = ("external-pentest", "web-app-api")


def _group(evidence: list[Evidence]) -> dict[str, list[Evidence]]:
    groups: dict[str, list[Evidence]] = {}
    for ev in evidence:
        if ev.source == "zap_passive" and ev.kind == "zap_alert":
            groups.setdefault(ev.data["plugin_id"], []).append(ev)
    return groups


def web_hygiene_findings(evidence: list[Evidence]) -> list[Finding]:
    """One finding per ZAP rule, citing every alert behind it."""
    findings = []
    for plugin_id, alerts in sorted(_group(evidence).items()):
        hosts = sorted({a.data["host"] for a in alerts})
        name = alerts[0].data["alert"]
        if plugin_id in MIXED_CONTENT_RULES:
            tier = Tier.ASK
        else:
            tier = Tier.BACKGROUND
        shown = ", ".join(hosts[:5]) + (f" and {len(hosts) - 5} more" if len(hosts) > 5 else "")
        findings.append(Finding(
            id=f"web_hygiene:{plugin_id}", rule="web_hygiene", title=name,
            detail=f"ZAP passive scan of the home pages flagged \"{name}\" on {len(hosts)} host(s): {shown}.",
            tier=tier, evidence_ids=tuple(a.id for a in alerts), lenses=FINDING_LENSES,
        ))
    return findings
