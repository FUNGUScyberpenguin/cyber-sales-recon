"""Pattern tables: server banners, Linux distributions, certifications, and trust-platform vendors.

Every name pattern is anchored with word boundaries. "Get the Acme advantage" contains
the letters "vanta", but it is not the vendor Vanta.
"""
from __future__ import annotations

import re

# Distributions that backport security fixes into old version numbers.
BACKPORTING_DISTROS = {"redhat", "debian", "ubuntu", "suse"}

_DISTRO_WORDS = (
    ("redhat", r"red\s?hat|rhel|centos|rocky|alma\s?linux|almalinux|oracle\s?linux|fedora"),
    ("ubuntu", r"ubuntu"),
    ("debian", r"debian|raspbian"),
    ("suse", r"suse|sles|opensuse"),
    ("other", r"alpine|amazon|freebsd|openbsd|win32|win64|unix"),
)
_DISTRO_RES = [(tag, re.compile(rf"\b(?:{words})\b", re.I)) for tag, words in _DISTRO_WORDS]
_PRODUCT_VERSION = re.compile(r"\b([A-Za-z][A-Za-z0-9._+-]*)/(\d+(?:\.\d+){0,3}[A-Za-z0-9._+~-]*)")
_PAREN = re.compile(r"\(([^)]*)\)")
# Headers that carry a software banner, and a product name to use when the header names none.
BANNER_HEADERS = {"server": None, "x-powered-by": None, "x-aspnet-version": "ASP.NET",
                  "x-aspnetmvc-version": "ASP.NET MVC", "x-generator": None}
CANONICAL_PRODUCT = {"apache": "Apache", "nginx": "nginx", "openssh": "OpenSSH", "php": "PHP",
                     "microsoft-iis": "Microsoft-IIS", "openssl": "OpenSSL", "tomcat": "Tomcat",
                     "apache-coyote": "Apache-Coyote", "lighttpd": "lighttpd", "jetty": "Jetty"}


# Packagers stamp the distribution into the version itself: PHP/8.1.2-1ubuntu2.14, nginx/1.18.0-6deb11u3.
_VERSION_TAGS = (("ubuntu", re.compile(r"ubuntu", re.I)), ("debian", re.compile(r"[+~-]?deb\d+u\d+|[+~]deb\d+", re.I)),
                 ("redhat", re.compile(r"\.el\d+(?:_\d+)?\b|\.rhel", re.I)), ("suse", re.compile(r"\.sle\d|suse", re.I)))


def distro_tag(text: str) -> str:
    """'redhat', 'debian', 'ubuntu', 'suse', 'other', or '' when the banner names none."""
    for tag, rx in _DISTRO_RES:
        if rx.search(text):
            return tag
    for tag, rx in _VERSION_TAGS:
        if rx.search(text):
            return tag
    return ""


def parse_banner(header: str, value: str) -> list[dict]:
    """Software named in one banner header. Each item: product, version, distro, raw, header.

    A distribution tag belongs to the product it sits next to (PHP/8.1.2-1ubuntu2). A product with no
    tag of its own takes the one on the header ("Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips")."""
    out = []
    header_tag = distro_tag(" ".join(_PAREN.findall(value)) or value)
    matches = list(_PRODUCT_VERSION.finditer(value))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(value)
        own = distro_tag(value[m.start():end])
        product, version = m.group(1), m.group(2)
        out.append({"product": CANONICAL_PRODUCT.get(product.lower(), product), "version": version,
                    "distro": own or header_tag, "raw": value.strip(), "header": header})
    if not out and BANNER_HEADERS.get(header) and re.search(r"\d", value):
        out.append({"product": BANNER_HEADERS[header], "version": value.strip(), "distro": "",
                    "raw": value.strip(), "header": header})
    return out


def extract_banners(headers: list[tuple[str, str]]) -> list[dict]:
    seen, out = set(), []
    for name, value in headers:
        key = name.lower()
        if key in BANNER_HEADERS:
            for b in parse_banner(key, value):
                ident = (b["product"].lower(), b["version"], b["header"])
                if ident not in seen:
                    seen.add(ident)
                    out.append(b)
    return out


CERTIFICATIONS = {
    "SOC 2 Type 2": r"soc\s?2\s*(?:type\s*(?:2|ii)\b|\(?type\s*(?:2|ii)\)?)",
    "SOC 2 Type 1": r"soc\s?2\s*type\s*(?:1|i)\b",
    "SOC 2": r"soc\s?2\b",
    "SOC 3": r"soc\s?3\b",
    "ISO 27001": r"iso(?:/iec)?\s?27001\b",
    "ISO 27701": r"iso(?:/iec)?\s?27701\b",
    "ISO 42001": r"iso(?:/iec)?\s?42001\b",
    "HIPAA": r"hipaa\b",
    "PCI DSS": r"pci[\s-]?dss\b",
    "GDPR": r"gdpr\b",
    "FedRAMP": r"fedramp\b",
    "HITRUST": r"hitrust\b",
    "CSA STAR": r"csa\s+star\b",
    "NIST 800-53": r"nist\s*(?:sp\s*)?800-53\b",
    "CMMC": r"cmmc\b",
}
_CERT_RES = {name: re.compile(rf"(?<![A-Za-z0-9]){rx}", re.I) for name, rx in CERTIFICATIONS.items()}

TRUST_VENDORS = {
    "Vanta": r"vanta", "Drata": r"drata", "Secureframe": r"secureframe", "SafeBase": r"safebase",
    "Conveyor": r"conveyor", "Whistic": r"whistic", "Thoropass": r"thoropass", "Sprinto": r"sprinto",
    "Scrut": r"scrut", "TrustCloud": r"trustcloud", "Hyperproof": r"hyperproof", "OneTrust": r"onetrust",
    "Tugboat Logic": r"tugboat\s+logic", "Laika": r"laika",
}
_VENDOR_RES = {name: re.compile(rf"(?<![A-Za-z0-9]){rx}(?![A-Za-z0-9])", re.I) for name, rx in TRUST_VENDORS.items()}
# Hosts that serve trust pages for other companies.
TRUST_PLATFORM_HOSTS = {
    "vanta.com": "Vanta", "drata.com": "Drata", "secureframe.com": "Secureframe", "safebase.io": "SafeBase",
    "conveyor.com": "Conveyor", "whistic.com": "Whistic", "thoropass.com": "Thoropass",
    "sprinto.com": "Sprinto", "trustcloud.ai": "TrustCloud", "hyperproof.io": "Hyperproof",
    "onetrust.com": "OneTrust", "trust.page": "", "trustarc.com": "TrustArc",
}


def find_certifications(text: str) -> list[str]:
    """Certifications named in text. A more specific match hides its general form (SOC 2 Type 2 hides SOC 2)."""
    found = [name for name, rx in _CERT_RES.items() if rx.search(text)]
    if "SOC 2 Type 2" in found or "SOC 2 Type 1" in found:
        found = [f for f in found if f != "SOC 2"]
    return found


def find_vendors(text: str) -> list[str]:
    return [name for name, rx in _VENDOR_RES.items() if rx.search(text)]


def platform_vendor(host: str) -> tuple[bool, str]:
    """(is a trust-platform host, vendor name) for a hostname."""
    host = host.lower()
    for suffix, vendor in TRUST_PLATFORM_HOSTS.items():
        if host == suffix or host.endswith("." + suffix):
            return True, vendor
    return False, ""
