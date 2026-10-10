from datetime import datetime, timedelta, timezone

from reconbrief.models import Tier, Tri
from reconbrief.sources.common import make_evidence
from tests.rule_helpers import D, cert, findings, host_dns, page, txt


def dns_mx(*records):
    return make_evidence("dns_records", "dns_record", f"{D} MX", Tri.FOUND, records=list(records) or ["10 mail.acme.com."])


# ---- email spoofing --------------------------------------------------------------------------

def test_unknown_spf_yields_no_finding():
    f = findings([dns_mx(), make_evidence("dns_records", "spf", D, Tri.UNKNOWN, error="timeout"),
                  make_evidence("dns_records", "dmarc", f"_dmarc.{D}", Tri.UNKNOWN, error="timeout")])
    assert not [i for i in f if i.startswith("email_spoofing")]


def test_absent_spf_and_dmarc_on_a_mail_domain_are_ask():
    f = findings([dns_mx(), make_evidence("dns_records", "spf", D, Tri.ABSENT),
                  make_evidence("dns_records", "dmarc", f"_dmarc.{D}", Tri.ABSENT)])
    assert f["email_spoofing:spf_missing"].tier is Tier.ASK
    assert f["email_spoofing:dmarc_missing"].tier is Tier.ASK


def test_dmarc_none_and_open_spf():
    f = findings([txt("spf", D, Tri.FOUND, "v=spf1 include:_spf.google.com +all"),
                  txt("dmarc", f"_dmarc.{D}", Tri.FOUND, "v=DMARC1; p=none; rua=mailto:x@acme.com")])
    assert f["email_spoofing:spf_open"].tier is Tier.ASK
    assert f["email_spoofing:dmarc_monitor_only"].tier is Tier.BACKGROUND


def test_strict_spf_and_dmarc_are_clean():
    f = findings([txt("spf", D, Tri.FOUND, "v=spf1 include:_spf.google.com -all"),
                  txt("dmarc", f"_dmarc.{D}", Tri.FOUND, "v=DMARC1; p=reject")])
    assert not [i for i in f if i.startswith("email_spoofing")]


# ---- domain registration ---------------------------------------------------------------------

def rdap(**data):
    base = dict(transfer_lock=True, registrar="Reg", expires="2099-01-01T00:00:00Z", registered="2010-01-01T00:00:00Z", age_days=5000)
    base.update(data)
    return make_evidence("rdap", "rdap_domain", D, Tri.FOUND, **base)


def test_registration_findings():
    soon = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    f = findings([rdap(transfer_lock=False, expires=soon, age_days=30)])
    assert {"domain_registration:no_transfer_lock", "domain_registration:expiring", "domain_registration:recent"} <= set(f)


def test_locked_domain_has_no_registration_finding_and_unknown_lock_is_silent():
    assert not findings([rdap()])
    assert not findings([rdap(transfer_lock=None)])
    assert not findings([make_evidence("rdap", "rdap_domain", D, Tri.UNKNOWN, error="timeout")])


# ---- dangling DNS ----------------------------------------------------------------------------

def test_dangling_cname_on_takeover_service_is_a_lead():
    ev = make_evidence("host_resolution", "dangling_cname", "docs.acme.com", Tri.FOUND,
                       chain=["docs.acme.com", "acme.github.io"], target="acme.github.io")
    assert findings([ev])["dangling_dns:cname"].tier is Tier.LEAD


def test_dangling_cname_elsewhere_is_ask_and_m365_names_are_skipped():
    ev = make_evidence("host_resolution", "dangling_cname", "old.acme.com", Tri.FOUND, chain=[], target="gone.example.net")
    assert findings([ev])["dangling_dns:cname"].tier is Tier.ASK
    m365 = make_evidence("dns_records", "m365_name", "sip.acme.com", Tri.FOUND, chain=[], points_to_microsoft=True)
    dang = make_evidence("dns_records", "dangling_cname", "sip.acme.com", Tri.FOUND, chain=[], target="sipdir.online.lync.com")
    assert not findings([m365, dang])


# ---- non-production hosts --------------------------------------------------------------------

def test_strong_words_count_without_a_page():
    f = findings([host_dns("staging.acme.com"), host_dns("www.acme.com"), host_dns("latest.acme.com")])
    assert f["non_production_hosts:strong"].tier is Tier.ASK
    assert "staging.acme.com" in f["non_production_hosts:strong"].detail
    assert "latest" not in f["non_production_hosts:strong"].detail  # 'test' inside a word is not a match


def test_weak_word_needs_a_page_signal():
    assert not [i for i in findings([host_dns("demo.acme.com"), page("demo.acme.com", title="Acme")])
                if i.startswith("non_production_hosts")]
    f = findings([host_dns("demo.acme.com"), page("demo.acme.com", title="Acme Demo")])
    assert f["non_production_hosts:weak"].tier is Tier.BACKGROUND
    f = findings([host_dns("beta.acme.com"), page("beta.acme.com", title="Welcome", has_password_form=True)])
    assert "non_production_hosts:weak" in f


def test_wildcard_host_counts_only_with_a_different_page():
    wc = host_dns("dev.acme.com", wildcard=True)
    assert not findings([wc, page("dev.acme.com", live=False, wildcard_host=True)])
    assert "non_production_hosts:strong" in findings([wc, page("dev.acme.com", live=True, wildcard_host=True)])


def test_unknown_wildcard_state_is_not_a_finding():
    ev = make_evidence("host_resolution", "host_dns", "dev.acme.com", Tri.FOUND, chain=[], addresses=["93.184.216.34"],
                       matches_wildcard=None)
    assert not findings([ev])


# ---- certificates ----------------------------------------------------------------------------

def test_certificate_issues():
    f = findings([page("www.acme.com"), cert("www.acme.com", expired=True, days_left=-30),
                  page("vpn.acme.com"), cert("vpn.acme.com", self_signed=True, name_matches_host=False),
                  page("old.acme.com"), cert("old.acme.com", expired=True, days_left=-5)])
    assert f["certificate_issues:expired_main"].tier is Tier.LEAD
    assert "old.acme.com" in f["certificate_issues:expired"].detail
    assert f["certificate_issues:self_signed"].tier is Tier.ASK
    assert f["certificate_issues:name_mismatch"].tier is Tier.ASK


def test_microsoft_service_names_get_no_certificate_or_portal_finding():
    m365 = make_evidence("dns_records", "m365_name", "autodiscover.acme.com", Tri.FOUND, chain=[], points_to_microsoft=True)
    f = findings([m365, page("autodiscover.acme.com", has_password_form=True, title="Sign in"),
                  cert("autodiscover.acme.com", expired=True)])
    assert not f


def test_wildcard_page_gets_no_certificate_finding():
    assert not findings([page("x.acme.com", live=False, wildcard_host=True), cert("x.acme.com", expired=True)])


def test_internal_names_in_certificates():
    f = findings([page("www.acme.com"), cert("www.acme.com", san=["www.acme.com", "db01.corp", "10.0.0.5", "intranet"])])
    assert f["internal_names_in_certificates:san"].tier is Tier.BACKGROUND


# ---- login portals ---------------------------------------------------------------------------

def test_marketing_page_that_names_products_yields_no_portal_finding():
    p = page("www.acme.com", title="Acme works with Jenkins, Okta and Citrix Gateway",
             vendor_mentions=["Okta"], links=[{"href": "https://acme.com/login", "text": "Sign in"}])
    assert "login_portals:all" not in findings([p])


def test_marketing_paths_are_not_login_paths():
    for path in ("/solutions/sso/", "/vpn/", "/auth/"):
        p = page("www.acme.com", title="Acme", final_url=f"https://www.acme.com{path}")
        assert "login_portals:all" not in findings([p])


def test_password_form_is_a_portal():
    p = page("app.acme.com", title="Acme", has_password_form=True)
    assert findings([p])["login_portals:all"].tier is Tier.BACKGROUND


def test_login_title_and_login_path_are_portals():
    assert "login_portals:all" in findings([page("a.acme.com", title="Sign in - Acme")])
    assert "login_portals:all" in findings([page("b.acme.com", title="Acme", final_url="https://b.acme.com/auth/login")])


def test_product_cookie_and_header_identify_the_product():
    f = findings([page("vpn.acme.com", title="Acme", set_cookie_names=["SVPNCOOKIE"])])
    assert f["login_portals:all"].tier is Tier.ASK and "Fortinet" in f["login_portals:all"].detail
    f = findings([page("mail.acme.com", title="Mail", headers=[("X-OWA-Version", "15.2")])])
    assert "Outlook on the web" in f["login_portals:all"].detail


def test_product_in_title_counts_only_on_a_login_page():
    f = findings([page("ci.acme.com", title="Sign in - Jenkins", has_password_form=True)])
    assert "Jenkins" in f["login_portals:all"].detail


# ---- transport, headers, software ------------------------------------------------------------

def test_plain_http_and_password_form_over_http():
    f = findings([page("old.acme.com", scheme="http")])
    assert f["plain_http:no_https"].tier is Tier.ASK
    f = findings([page("old.acme.com", scheme="http", has_password_form=True)])
    assert f["plain_http:no_https"].tier is Tier.LEAD


def test_security_headers_missing_and_present():
    f = findings([page("www.acme.com", headers=[("Strict-Transport-Security", "max-age=1")])])
    assert "Strict-Transport-Security" not in f["security_headers:missing"].detail
    assert "Content-Security-Policy is missing" in f["security_headers:missing"].detail
    full = [("Strict-Transport-Security", "x"), ("Content-Security-Policy", "frame-ancestors 'none'"),
            ("X-Content-Type-Options", "nosniff"), ("Permissions-Policy", "x")]
    assert "security_headers:missing" not in findings([page("www.acme.com", headers=full)])


def test_version_disclosure_and_tech_stack():
    b = [{"product": "nginx", "version": "1.18.0", "distro": "", "raw": "nginx/1.18.0", "header": "server"}]
    f = findings([page("www.acme.com", banners=b, generator="WordPress 6.4")])
    assert "nginx 1.18.0" in f["version_disclosure:banners"].detail
    assert "WordPress" in f["tech_stack:summary"].detail


def vuln(product, version, backports=False, kev=(), score=9.8, distros=()):
    return make_evidence("vulnerabilities", "vuln_lookup", f"{product} {version}", Tri.FOUND, product=product, version=version,
                         hosts=["www.acme.com"], banners=[f"{product}/{version}"], distros=list(distros), backports=backports,
                         cve_count=3, cves=[{"id": "CVE-1", "score": score, "kev": bool(kev)}], kev_ids=list(kev))


def test_red_hat_banner_is_background_at_most():
    f = findings([page("www.acme.com"), vuln("Apache", "2.4.6", backports=True, distros=["redhat"])])
    assert f["vulnerable_software:apache-2.4.6"].tier is Tier.BACKGROUND


def test_plain_version_is_ask_at_most_and_kev_is_a_lead():
    f = findings([page("www.acme.com"), vuln("nginx", "1.18.0")])
    assert f["vulnerable_software:nginx-1.18.0"].tier is Tier.ASK
    f = findings([page("www.acme.com"), vuln("Apache", "2.4.49", kev=["CVE-2021-41773"])])
    assert f["vulnerable_software:apache-2.4.49"].tier is Tier.LEAD
    f = findings([page("www.acme.com"), vuln("Apache", "2.4.6", backports=True, kev=["CVE-2017-1"], distros=["redhat"])])
    assert f["vulnerable_software:apache-2.4.6"].tier is Tier.LEAD


def test_unknown_lookup_is_silent():
    unknown = make_evidence("vulnerabilities", "vuln_lookup", "nginx 1.18.0", Tri.UNKNOWN, error="timeout")
    assert not findings([unknown])


def test_api_docs_default_pages_and_ai_exposure():
    f = findings([page("api.acme.com", title="Swagger UI"), page("x.acme.com", title="Welcome to nginx!"),
                  page("y.acme.com", title="Index of /backup"),
                  page("www.acme.com", script_srcs=["https://cdn.botpress.cloud/webchat/v1/inject.js"]),
                  page("help.acme.com", custom_elements=["elevenlabs-convai"])])
    assert f["api_docs:interactive"].tier is Tier.ASK
    assert f["default_pages:nginx-default-page"].tier is Tier.BACKGROUND
    assert f["default_pages:directory-listing"].tier is Tier.ASK
    assert "www.acme.com" in f["ai_exposure:widgets"].detail and "help.acme.com" in f["ai_exposure:widgets"].detail


def test_ai_words_in_body_text_do_not_count():
    p = page("www.acme.com", title="Our AI platform", vendor_mentions=["OpenAI"], text="We use OpenAI api.openai.com ChatGPT")
    assert "ai_exposure:widgets" not in findings([p])


# ---- trust and compliance --------------------------------------------------------------------

def trust_center(state, **data):
    return make_evidence("trust", "trust_center", D, state, **data)


def test_dns_only_run_reports_no_trust_center_absence():
    dns_only = [dns_mx(), txt("spf", D, Tri.FOUND, "v=spf1 -all"), host_dns("www.acme.com")]
    f = findings(dns_only)
    assert not [i for i in f if i.startswith("trust_compliance")]
    f = findings(dns_only + [trust_center(Tri.UNKNOWN, reason="homepage not loaded")])
    assert not [i for i in f if i.startswith("trust_compliance")]


def test_absent_trust_center_with_certification_claims_is_ask():
    claim = page("www.acme.com", title="Acme", certification_mentions=["SOC 2 Type 2"])
    f = findings([claim, trust_center(Tri.ABSENT, candidates_checked=["https://trust.acme.com/"])])
    assert f["trust_compliance:claims_without_trust_page"].tier is Tier.ASK
    assert "SOC 2 Type 2" in f["trust_compliance:claims_without_trust_page"].detail
    assert f["compliance_drivers:named_frameworks"].tier is Tier.BACKGROUND


def test_absent_trust_center_without_claims_is_background():
    f = findings([page("www.acme.com"), trust_center(Tri.ABSENT, candidates_checked=[])])
    assert f["trust_compliance:no_trust_center"].tier is Tier.BACKGROUND


def test_trust_center_found_and_security_txt():
    f = findings([trust_center(Tri.FOUND, url="https://trust.acme.com/", platform="Vanta", certifications=["HIPAA"]),
                  make_evidence("trust", "security_txt", D, Tri.ABSENT)])
    assert "Vanta" in f["trust_compliance:trust_center"].detail
    assert f["trust_compliance:no_security_txt"].tier is Tier.BACKGROUND
    assert f["compliance_drivers:named_frameworks"].tier is Tier.ASK  # HIPAA is regulatory


def test_sec_registrant_driver():
    prof = make_evidence("company", "company_profile", D, Tri.FOUND, legal_name="Acme Inc", tickers=["ACME"], cik=1)
    assert "compliance_drivers:sec_registrant" in findings([prof])


# ---- hosts -----------------------------------------------------------------------------------

def test_internal_addresses_published_in_public_dns():
    f = findings([host_dns("intranet.acme.com", addresses=["10.0.0.5"]), host_dns("mixed.acme.com", addresses=["10.0.0.6", "93.184.216.35"])])
    finding = f["internal_addresses:public_dns"]
    assert finding.title == "Internal addresses published in public DNS" and finding.tier is Tier.BACKGROUND
    assert "intranet.acme.com" in finding.detail and "mixed.acme.com" not in finding.detail


def test_stale_host_has_dns_but_a_long_expired_certificate():
    old = make_evidence("certificate_transparency", "ct_hostname", "legacy.acme.com", Tri.FOUND, not_after="2020-01-01T00:00:00")
    f = findings([host_dns("legacy.acme.com"), old])
    assert f["stale_hosts:dns_without_certificate"].tier is Tier.BACKGROUND
    assert "stale_hosts:dns_without_certificate" not in findings([host_dns("legacy.acme.com"), old, page("legacy.acme.com")])


def test_attack_surface_counts_hosts():
    ct = make_evidence("certificate_transparency", "ct_hostname", "www.acme.com", Tri.FOUND, not_after="2099-01-01T00:00:00")
    f = findings([ct, host_dns("www.acme.com"), page("www.acme.com")])
    assert "1 hostnames found" in f["attack_surface:summary"].detail and "1 answered with a web page" in f["attack_surface:summary"].detail


def test_every_finding_cites_evidence_that_exists():
    ev = [host_dns("staging.acme.com"), page("www.acme.com"), cert("www.acme.com", expired=True)]
    ids = {e.id for e in ev}
    for f in findings(ev).values():
        assert set(f.evidence_ids) <= ids
