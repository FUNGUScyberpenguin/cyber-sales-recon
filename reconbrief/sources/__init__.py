"""Discovery sources. Each one writes evidence and reports its own health."""
from __future__ import annotations

from reconbrief.pipeline import Source


def discovery_sources() -> list[Source]:
    from reconbrief.sources.archive import UrlscanHostnames, WaybackHostnames
    from reconbrief.sources.ct import CertificateTransparency
    from reconbrief.sources.dns_records import DnsRecords, HostDns
    from reconbrief.sources.network import CloudRanges, M365Tenant, RipeStat
    from reconbrief.sources.rdap import Rdap

    return [
        DnsRecords(), CertificateTransparency(), Rdap(), WaybackHostnames(), UrlscanHostnames(),
        M365Tenant(), HostDns(), RipeStat(), CloudRanges(),
    ]
