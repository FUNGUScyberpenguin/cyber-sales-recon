"""One recon run: preflight, sources, rules, recommendation, and the two output files."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import reconbrief
from reconbrief.models import Evidence, Finding, Health, SourceHealth, Tier, Tri, now_iso
from reconbrief.pipeline import Context, Pipeline
from reconbrief.preflight import PreflightResult, run_preflight
from reconbrief.recommend import Offering, recommend
from reconbrief.rules import run_rules
from reconbrief.rules.common import TIER_ORDER
from reconbrief.sources import discovery_sources, page_sources
from reconbrief.sources.common import HOST_RE

SCHEMA = 1
TOP_FINDINGS = 8
DETAIL_CHARS = 280


class BadDomain(ValueError):
    pass


def clean_domain(text: str) -> str:
    """'https://WWW.Acme.com/path' becomes 'acme.com'. Raises BadDomain for anything that isn't a hostname."""
    host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text.strip().lower()).split("/")[0].split("?")[0].split("#")[0]
    host = host.split("@")[-1].split(":")[0].rstrip(".")
    host = host[4:] if host.startswith("www.") else host
    if not HOST_RE.match(host):
        raise BadDomain(f"'{text}' is not a domain name")
    return host


@dataclass
class RunOutput:
    bundle: dict
    snapshot: dict
    blocked: PreflightResult | None = None


def _not_checked(health: list[SourceHealth], evidence: list[Evidence]) -> list[dict]:
    rows = [h.to_dict() for h in health if h.status is not Health.OK]
    unknown: dict[str, int] = {}
    for e in evidence:
        if e.state is Tri.UNKNOWN:
            unknown[e.source] = unknown.get(e.source, 0) + 1
    return [{"source": r["source"], "status": r["status"], "detail": r["detail"] or "not checked",
             "unknown_checks": unknown.get(r["source"], 0)} for r in rows]


def build_snapshot(domain: str, run_at: str, evidence: list[Evidence], findings: list[Finding],
                   health: list[SourceHealth], recommendation: dict | None) -> dict:
    pages = [e for e in evidence if e.kind == "web_page" and e.source == "page_loader"]
    discovered = {e.subject for e in evidence if e.kind in ("ct_hostname", "archive_hostname", "urlscan_hostname")
                  and e.state is Tri.FOUND}
    tiers = {t.value: sum(f.tier is t for f in findings) for t in Tier}
    top = sorted(findings, key=lambda f: (TIER_ORDER[f.tier], f.id))[:TOP_FINDINGS]
    return {
        "schema": SCHEMA, "domain": domain, "run_at": run_at, "engine": reconbrief.__version__,
        "counts": {
            "hostnames_found": len(discovered),
            "web_pages_loaded": sum(p.state is Tri.FOUND for p in pages),
            "live_hosts": sum(p.state is Tri.FOUND and p.data.get("live") is True for p in pages),
            "findings": len(findings), "by_tier": tiers,
        },
        "top_findings": [{"id": f.id, "title": f.title, "tier": f.tier.value,
                          "detail": f.detail[:DETAIL_CHARS], "lenses": list(f.lenses)} for f in top],
        "not_checked": _not_checked(health, evidence),
        "recommendation": recommendation,
    }


def blocked_snapshot(domain: str, run_at: str, preflight: PreflightResult) -> dict:
    return {"schema": SCHEMA, "domain": domain, "run_at": run_at, "engine": reconbrief.__version__,
            "blocked": True, "preflight": preflight.to_dict(), "message": preflight.message()}


def run_recon(domain: str, out_dir: Path, company_hint: str = "", offerings: list[Offering] | None = None,
              data_dir: Path | None = None, ctx: Context | None = None, sources: list | None = None,
              preflight_hosts: dict[str, str] | None = None) -> RunOutput:
    """Run preflight, then every source, then the rules. Writes bundle.json and snapshot.json to out_dir.

    If preflight finds a blocked or unreachable required host, nothing else runs and only snapshot.json
    is written, naming the hosts."""
    domain = clean_domain(domain)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ctx = ctx or Context.create(domain, company_hint, data_dir)
    run_at = now_iso()
    pre = run_preflight(ctx.http, preflight_hosts)
    if not pre.ok:
        snap = blocked_snapshot(domain, run_at, pre)
        (out_dir / "bundle.json").unlink(missing_ok=True)  # an old bundle must not sit beside a blocked run
        (out_dir / "snapshot.json").write_text(json.dumps(snap, indent=2, default=str))
        return RunOutput({}, snap, pre)
    result = Pipeline(sources if sources is not None else discovery_sources() + page_sources()).run(ctx)
    findings, rule_problems = run_rules(result.evidence, domain)
    health = result.health + rule_problems
    recommendation = recommend(offerings, findings) if offerings else None
    bundle = {
        "schema": SCHEMA, "engine": reconbrief.__version__, "domain": domain, "run_at": run_at,
        "company_hint": company_hint, "preflight": pre.to_dict(),
        "sources": [h.to_dict() for h in health],
        "evidence": [e.to_dict() for e in result.evidence],
        "findings": [f.to_dict() for f in findings],
        "recommendation": recommendation,
    }
    snap = build_snapshot(domain, run_at, result.evidence, findings, health, recommendation)
    (out_dir / "bundle.json").write_text(json.dumps(bundle, indent=2, default=str))
    (out_dir / "snapshot.json").write_text(json.dumps(snap, indent=2, default=str))
    return RunOutput(bundle, snap)
