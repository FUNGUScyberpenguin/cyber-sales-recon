"""Discovery sources. Each writes evidence; none writes findings."""
from reconbrief.sources.certificates import CertificateTransparency
from reconbrief.sources.dns_records import DnsRecords, HostResolution
from reconbrief.sources.history import Urlscan, Wayback
from reconbrief.sources.network import CloudRanges, M365Tenant, RipeStat
from reconbrief.sources.rdap import Rdap


def discovery_sources() -> list:
    return [DnsRecords(), CertificateTransparency(), Rdap(), Wayback(), Urlscan(), M365Tenant(),
            HostResolution(), CloudRanges(), RipeStat()]
