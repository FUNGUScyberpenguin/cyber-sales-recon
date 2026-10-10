"""Rules turn evidence into findings. They read only what the sources already wrote."""
from __future__ import annotations

from reconbrief.models import Evidence, Finding, Health, SourceHealth
from reconbrief.rules import hosts, mail, trust, web
from reconbrief.rules.common import TIER_ORDER, Index
from reconbrief.rules_web_hygiene import web_hygiene_findings

RULES = (
    mail.email_spoofing, mail.domain_registration, mail.dangling_dns,
    hosts.non_production_hosts, hosts.internal_names_in_certificates, hosts.stale_hosts,
    hosts.internal_addresses, hosts.attack_surface,
    web.certificate_issues, web.login_portals, web.plain_http, web.security_headers,
    web.version_disclosure, web.vulnerable_software, web.api_docs, web.default_pages,
    web.tech_stack, web.ai_exposure,
    trust.trust_compliance, trust.compliance_drivers,
)


def run_rules(evidence: list[Evidence], domain: str) -> tuple[list[Finding], list[SourceHealth]]:
    """All findings, most important first. A rule that crashes is reported as failed; the others still run."""
    ix = Index(evidence, domain)
    findings: list[Finding] = []
    problems: list[SourceHealth] = []
    for rule in RULES:
        try:
            findings += rule(ix)
        except Exception as exc:
            problems.append(SourceHealth(f"rule:{rule.__name__}", Health.FAILED, f"{type(exc).__name__}: {exc}"))
    try:
        findings += web_hygiene_findings(evidence)
    except Exception as exc:
        problems.append(SourceHealth("rule:web_hygiene_findings", Health.FAILED, f"{type(exc).__name__}: {exc}"))
    unique = {f.id: f for f in findings}
    return sorted(unique.values(), key=lambda f: (TIER_ORDER[f.tier], f.id)), problems
