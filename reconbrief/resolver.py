"""DNS lookups with three-state results and TCP retry.

A timeout, SERVFAIL, or any other failure is UNKNOWN. Only NXDOMAIN and an
empty answer are ABSENT.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from reconbrief.models import Tri

FALLBACK_NAMESERVERS = ("1.1.1.1", "8.8.8.8")
UDP_ATTEMPTS = 3

# transport(query, nameserver, timeout, tcp) -> response message. Tests replace it.
Transport = Callable[[dns.message.Message, str, float, bool], dns.message.Message]


@dataclass(frozen=True)
class DnsResult:
    state: Tri
    records: tuple[str, ...] = ()
    error: str = ""
    ttl: int | None = None
    flags: dict[str, bool] = field(default_factory=dict)


def _network_transport(q: dns.message.Message, server: str, timeout: float, tcp: bool):
    if tcp:
        return dns.query.tcp(q, server, timeout=timeout)
    return dns.query.udp(q, server, timeout=timeout)


def _system_nameservers() -> list[str]:
    try:
        found = dns.resolver.Resolver().nameservers
    except Exception:
        found = []
    return [str(n) for n in found] or list(FALLBACK_NAMESERVERS)


def _rdata_text(rdata) -> str:
    strings = getattr(rdata, "strings", None)
    if strings is not None:  # TXT and SPF: join the character-strings of one record
        return b"".join(strings).decode("utf-8", "replace")
    return rdata.to_text()


class DnsResolver:
    def __init__(
        self,
        nameservers: list[str] | None = None,
        transport: Transport = _network_transport,
        timeout: float = 4.0,
    ) -> None:
        self.nameservers = nameservers or _system_nameservers()
        self.transport = transport
        self.timeout = timeout

    def query(self, name: str, rdtype: str) -> DnsResult:
        q = dns.message.make_query(name, rdtype)
        last_error = "no nameserver answered"
        for server in self.nameservers:
            response, error = self._ask(q, server)
            if response is None:
                last_error = error
                continue
            result = self._interpret(response, rdtype)
            if result.state is Tri.UNKNOWN:  # SERVFAIL or REFUSED: try the next nameserver
                last_error = result.error
                continue
            return result
        return DnsResult(Tri.UNKNOWN, error=last_error)

    def _ask(self, q: dns.message.Message, server: str):
        error = "timeout"
        for _ in range(UDP_ATTEMPTS):
            try:
                response = self.transport(q, server, self.timeout, False)
            except dns.exception.Timeout:
                error = "timeout"
                continue
            except Exception as exc:  # network error, malformed packet
                error = f"{type(exc).__name__}: {exc}"
                break
            if not response.flags & dns.flags.TC:
                return response, ""
            error = "truncated"
            break
        try:  # timeouts exhausted, a truncated answer, or a UDP error: retry over TCP
            return self.transport(q, server, self.timeout, True), ""
        except dns.exception.Timeout:
            return None, error if error != "truncated" else "timeout over tcp"
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"

    def _interpret(self, response: dns.message.Message, rdtype: str) -> DnsResult:
        rcode = response.rcode()
        flags = {"ad": bool(response.flags & dns.flags.AD)}
        if rcode == dns.rcode.NXDOMAIN:
            return DnsResult(Tri.ABSENT, error="NXDOMAIN", flags=flags)
        if rcode != dns.rcode.NOERROR:
            return DnsResult(Tri.UNKNOWN, error=dns.rcode.to_text(rcode), flags=flags)
        want = dns.rdatatype.from_text(rdtype)
        records: list[str] = []
        ttl = None
        for rrset in response.answer:
            if rrset.rdtype != want:
                continue
            ttl = rrset.ttl if ttl is None else min(ttl, rrset.ttl)
            records.extend(_rdata_text(r) for r in rrset)
        if not records:
            return DnsResult(Tri.ABSENT, error="no data", flags=flags)
        return DnsResult(Tri.FOUND, tuple(records), ttl=ttl, flags=flags)
