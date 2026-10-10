"""Rules from the pages the page loader read: certificates, portals, headers, software, and exposure."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from reconbrief.models import Evidence, Finding, Tier, Tri
from reconbrief.rules.common import Index, header, make_finding, shown
from reconbrief.sources.patterns import BACKPORTING_DISTROS

WEB_LENSES = ("external-pentest", "web-app-api")

# ---- certificates ----------------------------------------------------------------------------

CERT_LENSES = ("external-pentest", "continuous-exposure-management")
WEAK_SIGNATURES = {"md5", "sha1"}


def certificate_issues(ix: Index) -> list[Finding]:
    groups: dict[str, list[Evidence]] = {}
    lead_hosts = {ix.domain, f"www.{ix.domain}"}
    for cert in ix.kind("certificate", Tri.FOUND):
        host, d = cert.subject, cert.data
        if host in ix.m365_microsoft or not ix.page_ok(host):
            continue  # Microsoft's servers, or a wildcard host that is not a real host
        if d.get("expired"):
            groups.setdefault("expired_main" if host in lead_hosts else "expired", []).append(cert)
        elif d.get("not_yet_valid"):
            groups.setdefault("not_yet_valid", []).append(cert)
        elif isinstance(d.get("days_left"), int) and d["days_left"] <= 14:
            groups.setdefault("expiring_soon", []).append(cert)
        if d.get("self_signed"):
            groups.setdefault("self_signed", []).append(cert)
        if d.get("name_matches_host") is False:
            groups.setdefault("name_mismatch", []).append(cert)
        if (d.get("key_type") == "RSA" and (d.get("key_bits") or 4096) < 2048) \
                or str(d.get("signature_hash", "")).lower() in WEAK_SIGNATURES:
            groups.setdefault("weak", []).append(cert)
    spec = {
        "expired_main": ("Certificate on the main site has expired", Tier.LEAD, "{n} main-site certificate(s) expired: {h}."),
        "expired": ("Expired certificates", Tier.ASK, "{n} host(s) serve an expired certificate: {h}."),
        "not_yet_valid": ("Certificates that are not valid yet", Tier.ASK, "{n} host(s) serve a certificate whose start date is in the future: {h}."),
        "expiring_soon": ("Certificates expire within two weeks", Tier.ASK, "{n} certificate(s) expire within 14 days: {h}."),
        "self_signed": ("Self-signed certificates", Tier.ASK, "{n} host(s) serve a self-signed certificate: {h}."),
        "name_mismatch": ("Certificate name does not match the host", Tier.ASK, "{n} host(s) serve a certificate issued for other names: {h}."),
        "weak": ("Weak certificate keys or signatures", Tier.ASK, "{n} certificate(s) use a short RSA key or an MD5/SHA-1 signature: {h}."),
    }
    out = []
    for key, certs in groups.items():
        title, tier, text = spec[key]
        hosts = sorted({c.subject for c in certs})
        out.append(make_finding("certificate_issues", key, title, text.format(n=len(hosts), h=shown(hosts)),
                                tier, certs, CERT_LENSES))
    return out


# ---- login portals ---------------------------------------------------------------------------

LOGIN_TITLE = re.compile(r"^\s*(sign[\s-]?in|log[\s-]?in|login|logon|single sign[\s-]?on|sso)\b|"
                         r"[-|:]\s*(sign[\s-]?in|log[\s-]?in|login|logon)\s*$", re.I)
LOGIN_PATH = re.compile(r"/(log-?in|sign-?in|logon)(?:[/.]|$)", re.I)
# (product, kind) by strong signal. Header and cookie names are exact; cookies may be prefixes.
PRODUCT_HEADERS = {"x-owa-version": ("Outlook on the web", "remote_access"), "x-jenkins": ("Jenkins", "admin"),
                   "x-confluence-request-time": ("Confluence", "admin")}
PRODUCT_COOKIES = (("mrhsession", "F5 BIG-IP APM", "remote_access"), ("lastmrh_session", "F5 BIG-IP APM", "remote_access"),
                   ("svpncookie", "Fortinet SSL VPN", "remote_access"), ("nsc_aaac", "Citrix NetScaler Gateway", "remote_access"),
                   ("citrix_ns_id", "Citrix NetScaler Gateway", "remote_access"), ("dsid", "Pulse/Ivanti Connect Secure", "remote_access"),
                   ("webvpn", "Cisco ASA WebVPN", "remote_access"))
PRODUCT_TITLES = ((re.compile(r"\bOutlook(?: Web (?:App|Access))?\b", re.I), "Outlook on the web", "remote_access"),
                  (re.compile(r"\bGlobalProtect\b", re.I), "Palo Alto GlobalProtect", "remote_access"),
                  (re.compile(r"\bFortiGate\b", re.I), "Fortinet FortiGate", "remote_access"),
                  (re.compile(r"\b(?:Citrix Gateway|NetScaler Gateway|Citrix Workspace)\b", re.I), "Citrix Gateway", "remote_access"),
                  (re.compile(r"\b(?:Pulse|Ivanti) Connect Secure\b", re.I), "Pulse/Ivanti Connect Secure", "remote_access"),
                  (re.compile(r"\bSonicWall\b", re.I), "SonicWall", "remote_access"),
                  (re.compile(r"\bBIG-IP\b", re.I), "F5 BIG-IP", "remote_access"),
                  (re.compile(r"\bJenkins\b", re.I), "Jenkins", "admin"), (re.compile(r"\bGrafana\b", re.I), "Grafana", "admin"),
                  (re.compile(r"\bKibana\b", re.I), "Kibana", "admin"), (re.compile(r"\bphpMyAdmin\b", re.I), "phpMyAdmin", "admin"))


def portal_signals(page: Evidence) -> tuple[list[str], str, str]:
    """(signals, product, kind) from strong signals only. Words in the page body never count."""
    d, signals = page.data, []
    product, kind = "", ""
    title = d.get("title") or ""
    login_title = bool(LOGIN_TITLE.search(title))
    if login_title:
        signals.append("page title")
    if d.get("has_password_form"):
        signals.append("password form")
    path = urlsplit(d.get("final_url") or "").path
    status = d.get("status") or 0
    if LOGIN_PATH.search(path) and (200 <= status < 300 or status == 401):
        signals.append("login page loaded")
    for name, (prod, k) in PRODUCT_HEADERS.items():
        if header(page, name) is not None:
            signals.append(f"{name} header")
            product, kind = prod, k
    cookies = [c.lower() for c in d.get("set_cookie_names", [])]
    for prefix, prod, k in PRODUCT_COOKIES:
        if any(c.startswith(prefix) for c in cookies):
            signals.append("product cookie")
            product, kind = product or prod, kind or k
    if not product and (d.get("has_password_form") or login_title or "login page loaded" in signals):
        for rx, prod, k in PRODUCT_TITLES:  # a product in the title counts only on a page that is a login page
            if rx.search(title):
                product, kind = prod, k
                break
    return signals, product, kind


def login_portals(ix: Index) -> list[Finding]:
    hits: dict[str, tuple[str, str]] = {}
    evidence = []
    for page in ix.live_pages():
        signals, product, kind = portal_signals(page)
        if signals:
            hits[page.subject] = (product, kind)
            evidence.append(page)
    if not hits:
        return []
    named = sorted(f"{h} ({p})" if p else h for h, (p, _) in hits.items())
    tier = Tier.ASK if any(k for _, k in hits.values()) else Tier.BACKGROUND
    return [make_finding("login_portals", "all", "Login portals are reachable from the internet",
                         f"{len(hits)} host(s) show a login page: {shown(named)}.", tier, evidence,
                         ("external-pentest", "web-app-api", "red-team"))]


# ---- transport and headers -------------------------------------------------------------------

def plain_http(ix: Index) -> list[Finding]:
    http = [p for p in ix.live_pages() if p.data.get("scheme") == "http" and 200 <= (p.data.get("status") or 0) < 300]
    if not http:
        return []
    forms = [p for p in http if p.data.get("has_password_form")]
    tier = Tier.LEAD if forms else Tier.ASK
    detail = f"{len(http)} host(s) answered only over plain HTTP: {shown(sorted(p.subject for p in http))}."
    if forms:
        detail += f" A password form is served over HTTP on {shown(sorted(p.subject for p in forms))}."
    return [make_finding("plain_http", "no_https", "Hosts served without HTTPS", detail, tier, http, WEB_LENSES)]


HEADER_CHECKS = (
    ("Strict-Transport-Security", lambda p: header(p, "strict-transport-security") is None),
    ("Content-Security-Policy", lambda p: header(p, "content-security-policy") is None),
    ("clickjacking protection", lambda p: header(p, "x-frame-options") is None
     and "frame-ancestors" not in (header(p, "content-security-policy") or "").lower()),
    ("X-Content-Type-Options", lambda p: (header(p, "x-content-type-options") or "").lower() != "nosniff"),
    ("Permissions-Policy", lambda p: header(p, "permissions-policy") is None),
)


def security_headers(ix: Index) -> list[Finding]:
    pages = [p for p in ix.live_pages() if p.data.get("scheme") == "https" and 200 <= (p.data.get("status") or 0) < 300
             and "html" in (p.data.get("content_type") or "").lower() and "headers" in p.data]
    if not pages:
        return []
    missing: dict[str, list[Evidence]] = {}
    for name, absent in HEADER_CHECKS:
        for p in pages:
            if absent(p):
                missing.setdefault(name, []).append(p)
    if not missing:
        return []
    lines = [f"{name} is missing on {len(ps)} of {len(pages)} pages" for name, ps in missing.items()]
    evidence = [p for ps in missing.values() for p in ps]
    return [make_finding("security_headers", "missing", "Browser security headers are missing",
                         "; ".join(lines) + ".", Tier.BACKGROUND, evidence, WEB_LENSES)]


# ---- software --------------------------------------------------------------------------------

def version_disclosure(ix: Index) -> list[Finding]:
    seen: dict[str, list[Evidence]] = {}
    for p in ix.live_pages():
        for b in p.data.get("banners", []):
            if b.get("version"):
                seen.setdefault(f"{b['product']} {b['version']}", []).append(p)
    if not seen:
        return []
    pages = list({p.id: p for ps in seen.values() for p in ps}.values())
    return [make_finding("version_disclosure", "banners", "Server software versions are visible",
                         f"Response headers name {len(seen)} software version(s): {shown(sorted(seen))}.",
                         Tier.BACKGROUND, pages, WEB_LENSES)]


def vulnerable_software(ix: Index) -> list[Finding]:
    out = []
    for e in ix.kind("vuln_lookup", Tri.FOUND):
        d = e.data
        if not d.get("cve_count"):
            continue
        scores = [c["score"] for c in d["cves"] if c.get("score") is not None]
        top = max(scores) if scores else None
        kev = d.get("kev_ids", [])
        raw = "; ".join(d.get("banners", [])[:2])
        if kev:
            tier = Tier.LEAD  # a CISA KEV match lifts every cap
        elif d.get("backports"):
            tier = Tier.BACKGROUND  # Red Hat, Debian, Ubuntu and SUSE fix bugs without changing the version
        else:
            tier = Tier.ASK if top is not None and top >= 7.0 else Tier.BACKGROUND
        detail = (f"The banner on {shown(d['hosts'])} reports {d['product']} {d['version']} ({raw}). "
                  f"NVD lists {d['cve_count']} CVE(s) for that version"
                  + (f", highest score {top}" if top is not None else "") + ".")
        if kev:
            detail += f" CISA's known-exploited list includes {shown(kev)}."
        elif d.get("backports"):
            detail += f" The banner names {shown(d['distros'])}, which backports fixes into old version numbers."
        out.append(make_finding("vulnerable_software", f"{d['product']} {d['version']}".lower().replace(" ", "-"),
                                f"{d['product']} {d['version']} has known CVEs", detail, tier,
                                [e] + [p for p in ix.live_pages() if p.subject in d["hosts"]],
                                ("external-pentest", "continuous-exposure-management")))
    return out


# ---- page content ----------------------------------------------------------------------------

API_DOC_TITLE = re.compile(r"\b(swagger ui|redoc|graphiql|graphql playground)\b", re.I)
API_DOC_SCRIPT = re.compile(r"swagger-ui|redoc\.standalone|graphiql|graphql-playground", re.I)


def api_docs(ix: Index) -> list[Finding]:
    hits = [p for p in ix.live_pages() if API_DOC_TITLE.search(p.data.get("title") or "")
            or any(API_DOC_SCRIPT.search(s) for s in p.data.get("script_srcs", []))]
    if not hits:
        return []
    return [make_finding("api_docs", "interactive", "Interactive API documentation is public",
                         f"{len(hits)} host(s) serve an API explorer: {shown(sorted(p.subject for p in hits))}.",
                         Tier.ASK, hits, ("web-app-api", "external-pentest"))]


DEFAULT_TITLES = ((re.compile(r"^\s*index of /", re.I), "directory listing", Tier.ASK),
                  (re.compile(r"welcome to nginx", re.I), "nginx default page", Tier.BACKGROUND),
                  (re.compile(r"apache2? .*default page|test page for the apache", re.I), "Apache default page", Tier.BACKGROUND),
                  (re.compile(r"^\s*iis windows server|internet information services", re.I), "IIS default page", Tier.BACKGROUND),
                  (re.compile(r"^\s*apache tomcat", re.I), "Tomcat default page", Tier.BACKGROUND),
                  (re.compile(r"^\s*welcome to (centos|red hat|fedora)", re.I), "Linux default page", Tier.BACKGROUND))


def default_pages(ix: Index) -> list[Finding]:
    groups: dict[str, tuple[Tier, list[Evidence]]] = {}
    for p in ix.live_pages():
        for rx, label, tier in DEFAULT_TITLES:
            if rx.search(p.data.get("title") or ""):
                groups.setdefault(label, (tier, []))[1].append(p)
                break
    out = []
    for label, (tier, pages) in sorted(groups.items()):
        out.append(make_finding("default_pages", label.replace(" ", "-"),
                                f"Default page: {label}", f"{len(pages)} host(s) show a {label}: "
                                f"{shown(sorted(p.subject for p in pages))}.", tier, pages, WEB_LENSES))
    return out


def tech_stack(ix: Index) -> list[Finding]:
    generators, products = {}, {}
    for p in ix.live_pages():
        if p.data.get("generator"):
            generators.setdefault(p.data["generator"], []).append(p)
        for b in p.data.get("banners", []):
            products.setdefault(b["product"], []).append(p)
    if not generators and not products:
        return []
    parts = []
    if products:
        parts.append("servers report " + shown(sorted(products)))
    if generators:
        parts.append("pages are generated by " + shown(sorted(generators)))
    pages = list({p.id: p for ps in [*generators.values(), *products.values()] for p in ps}.values())
    text = "; ".join(parts)
    return [make_finding("tech_stack", "summary", "Technology in use", text[0].upper() + text[1:] + ".",
                         Tier.BACKGROUND, pages, ("web-app-api", "continuous-exposure-management"))]


# Script sources, iframes, form targets, and widget tags only. Page text never counts.
AI_VENDORS = re.compile(r"(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|"
                        r"cdn\.botpress\.cloud|botpress\.com|voiceflow\.com|chatbase\.co|elevenlabs\.io/convai|"
                        r"widget\.kapa\.ai|kapa\.ai|mendable\.ai|docsbot\.ai|landbot\.io|inkeep\.com|"
                        r"@n8n/chat|huggingface\.co|api\.cohere\.(?:com|ai)|api\.mistral\.ai)", re.I)
AI_ENDPOINT = re.compile(r"/(?:v1/chat/completions|api/chat|api/completions|api/assistant|api/ask)(?:[/?]|$)", re.I)
AI_ELEMENTS = {"elevenlabs-convai", "gradio-app", "df-messenger", "zapier-interfaces-chatbot-embed", "kapa-widget"}


def ai_exposure(ix: Index) -> list[Finding]:
    hits: dict[str, list[str]] = {}
    pages: list[Evidence] = []
    for p in ix.live_pages():
        d, why = p.data, []
        urls = [*d.get("script_srcs", []), *d.get("iframe_srcs", [])]
        why += [f"script or frame from {urlsplit(u).hostname}" for u in urls if AI_VENDORS.search(u)]
        why += ["AI API endpoint in a form or script" for u in [*urls, *d.get("form_actions", [])] if AI_ENDPOINT.search(urlsplit(u).path)]
        why += [f"<{el}> widget" for el in d.get("custom_elements", []) if el in AI_ELEMENTS]
        if why:
            hits[p.subject] = sorted(set(why))
            pages.append(p)
    if not hits:
        return []
    lines = [f"{h} ({'; '.join(w)})" for h, w in sorted(hits.items())]
    return [make_finding("ai_exposure", "widgets", "AI features are exposed on public pages",
                         f"{len(hits)} host(s) load an AI service or widget: {shown(lines, 3)}.",
                         Tier.ASK, pages, ("ai-red-teaming", "web-app-api"))]
