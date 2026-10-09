"""Sources. Each writes evidence; none writes findings."""
from reconbrief.sources.certificates import CertificateTransparency
from reconbrief.sources.company import CompanyProfile
from reconbrief.sources.dns_records import DnsRecords, HostResolution
from reconbrief.sources.history import Urlscan, Wayback
from reconbrief.sources.network import CloudRanges, M365Tenant, RipeStat
from reconbrief.sources.pages import PageLoader
from reconbrief.sources.rdap import Rdap
from reconbrief.sources.trust import TrustPosture
from reconbrief.sources.vulns import Vulnerabilities


def discovery_sources() -> list:
    return [DnsRecords(), CertificateTransparency(), Rdap(), Wayback(), Urlscan(), M365Tenant(),
            HostResolution(), CloudRanges(), RipeStat()]


def page_sources() -> list:
    """Run after discovery: the page loader (stage 3), then what is built on its pages (stage 4)."""
    return [PageLoader(), TrustPosture(), CompanyProfile(), Vulnerabilities()]
