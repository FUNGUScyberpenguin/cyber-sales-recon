"""Trust, compliance, and what regulators or customers may be asking this company for."""
from __future__ import annotations

from reconbrief.models import Evidence, Finding, Tier, Tri
from reconbrief.rules.common import Index, make_finding, parse_time, shown

LENSES = ("vciso-program-review", "external-pentest")
REGULATORY = {"HIPAA", "PCI DSS", "FedRAMP", "CMMC", "NIST 800-53", "HITRUST", "GDPR"}


def _claims(ix: Index) -> dict[str, list[Evidence]]:
    """Certification names the company states on its own pages, with the pages that state them."""
    claims: dict[str, list[Evidence]] = {}
    for p in ix.live_pages():
        for name in p.data.get("certification_mentions", []):
            claims.setdefault(name, []).append(p)
    for e in ix.kind("trust_center", Tri.FOUND):
        for name in e.data.get("certifications", []):
            claims.setdefault(name, []).append(e)
    return claims


def trust_compliance(ix: Index) -> list[Finding]:
    out: list[Finding] = []
    claims = _claims(ix)
    center = ix.one("trust_center", ix.domain)
    if center is not None and center.state is Tri.ABSENT:  # only produced when the trust check ran
        checked = len(center.data.get("candidates_checked", []))
        if claims:
            pages = [p for ps in claims.values() for p in ps]
            out.append(make_finding("trust_compliance", "claims_without_trust_page",
                                    "Compliance claims with no trust page",
                                    f"Public pages name {shown(sorted(claims))}, and no trust page was found "
                                    f"({checked} candidate page(s) checked).", Tier.ASK, [center] + pages, LENSES))
        else:
            out.append(make_finding("trust_compliance", "no_trust_center", "No trust center found",
                                    f"No trust or security page was found ({checked} candidate page(s) checked).",
                                    Tier.BACKGROUND, [center], LENSES))
    elif center is not None and center.state is Tri.FOUND:
        platform = f" on {center.data['platform']}" if center.data.get("platform") else ""
        names = center.data.get("certifications", [])
        out.append(make_finding("trust_compliance", "trust_center", "Trust center is published",
                                f"A trust page is live at {center.data.get('url', '')}{platform}"
                                + (f" and names {shown(names)}." if names else "."),
                                Tier.BACKGROUND, [center], LENSES))
    txt = ix.one("security_txt", ix.domain)
    if txt is not None and txt.state is Tri.ABSENT:
        out.append(make_finding("trust_compliance", "no_security_txt", "No security.txt file",
                                "No security.txt was found at /.well-known/security.txt.", Tier.BACKGROUND, [txt], LENSES))
    elif txt is not None and txt.state is Tri.FOUND and txt.data.get("expired") is True:
        out.append(make_finding("trust_compliance", "security_txt_expired", "security.txt has expired",
                                f"The security.txt file expired on {txt.data.get('expires', '')[:10]}.",
                                Tier.BACKGROUND, [txt], LENSES))
    return out


def compliance_drivers(ix: Index) -> list[Finding]:
    claims = _claims(ix)
    out: list[Finding] = []
    if claims:
        tier = Tier.ASK if REGULATORY & set(claims) else Tier.BACKGROUND
        evidence = list({e.id: e for es in claims.values() for e in es}.values())
        out.append(make_finding("compliance_drivers", "named_frameworks", "Compliance frameworks the company names",
                                f"Public pages name {shown(sorted(claims))}.", tier, evidence, LENSES))
    profile = ix.one("company_profile", ix.domain)
    if profile is not None and profile.state is Tri.FOUND and (profile.data.get("tickers") or profile.data.get("cik")):
        tickers = shown(profile.data.get("tickers", []))
        name = profile.data.get("legal_name") or "The company"
        out.append(make_finding("compliance_drivers", "sec_registrant", "Files with the SEC",
                                f"{name} is an SEC registrant" + (f" ({tickers})." if tickers else "."),
                                Tier.BACKGROUND, [profile], LENSES))
    return out
