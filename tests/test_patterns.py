import pytest

from reconbrief.sources.htmlsignals import parse_html
from reconbrief.sources.patterns import (distro_tag, extract_banners, find_certifications, find_vendors,
                                         platform_vendor)
from tests.helpers import recorded


def test_marketing_copy_names_no_vendor():
    assert find_vendors("Get the Acme advantage") == []  # "advantage" contains "vanta"
    assert find_vendors("Our scrutiny of drated, vantage and hyperproofing") == []
    assert find_vendors("We use Vanta and are listed on SafeBase.") == ["Vanta", "SafeBase"]
    assert find_vendors("vanta-powered trust center") == ["Vanta"]


@pytest.mark.parametrize("text, expected", [
    ("We are SOC 2 Type II audited", ["SOC 2 Type 2"]),
    ("SOC2 Type 2 report on request", ["SOC 2 Type 2"]),
    ("SOC 2 Type 1 only", ["SOC 2 Type 1"]),
    ("SOC 2 compliant", ["SOC 2"]),
    ("ISO/IEC 27001 and HIPAA", ["ISO 27001", "HIPAA"]),
    ("our unsoc 2000 and gdprs", []),
])
def test_certification_mentions(text, expected):
    assert find_certifications(text) == expected


@pytest.mark.parametrize("value, distro", [
    ("Apache/2.4.6 (CentOS)", "redhat"),
    ("Apache/2.4.37 (Red Hat Enterprise Linux)", "redhat"),
    ("Apache/2.4.41 (Ubuntu)", "ubuntu"),
    ("Apache/2.4.38 (Debian)", "debian"),
    ("Apache/2.4.51 (SUSE)", "suse"),
    ("nginx/1.18.0", ""),
    ("PHP/8.1.2-1ubuntu2.14", "ubuntu"),
    ("nginx/1.18.0-6deb11u3", "debian"),
    ("Apache/2.4.6 (Unix)", "other"),
])
def test_distribution_tags(value, distro):
    assert distro_tag(value) == distro


def test_banner_products_and_versions():
    headers = [("Server", "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16"), ("X-Powered-By", "PHP/5.4.16"),
               ("X-AspNet-Version", "4.0.30319"), ("Server", "cloudflare")]
    banners = extract_banners(headers)
    found = {(b["product"], b["version"], b["header"]): b["distro"] for b in banners}
    assert found[("Apache", "2.4.6", "server")] == "redhat"
    assert found[("OpenSSL", "1.0.2k-fips", "server")] == "redhat"
    assert ("PHP", "5.4.16", "x-powered-by") in found
    assert ("ASP.NET", "4.0.30319", "x-aspnet-version") in found
    assert not any(b["raw"] == "cloudflare" for b in banners)  # no version, no banner


def test_trust_platform_hosts():
    assert platform_vendor("acme.safebase.io") == (True, "SafeBase")
    assert platform_vendor("trust.vanta.com") == (True, "Vanta")
    assert platform_vendor("notvanta.com") == (False, "")


def test_html_signals_from_the_recorded_homepage():
    s = parse_html(recorded("home_example.html"), "https://example.com/")
    assert s.title == "Example Corp | Secure payments" and s.og_site_name == "Example Corp"
    assert s.has_password_form and s.form_actions == ["https://example.com/login"]
    assert "https://example.com/static/app.js" in s.script_srcs
    assert s.icon_hrefs == ["https://example.com/favicon.ico"] and s.custom_elements == ["chat-bubble"]
    assert {"href": "https://example.com/trust", "text": "Trust Center"} in s.links
    assert "SOC 2 Type II" in s.text and "Vanta" not in s.text  # script text is not page text


def test_each_product_gets_its_own_distribution_tag():
    banners = {b["product"]: b["distro"] for b in extract_banners(
        [("Server", "Apache/2.4.57 (Unix) PHP/8.1.2-1ubuntu2 OpenSSL/3.0.2")])}
    assert banners == {"Apache": "other", "PHP": "ubuntu", "OpenSSL": "other"}  # OpenSSL takes the header's tag
    banners = {b["product"]: b["distro"] for b in extract_banners([("Server", "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16")])}
    assert set(banners.values()) == {"redhat"}
