"""The address guard and the HTTP client built on it.

Every request to a prospect's host goes through AddressGuard: resolve the
host, keep only globally routable addresses, connect to an address that was
checked, and follow redirects by hand through the same check.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import reconbrief
from reconbrief.models import Tri
from reconbrief.resolver import DnsResolver

REPO_URL = "https://github.com/FUNGUScyberpenguin/cyber-sales-recon"
USER_AGENT = f"reconbrief/{reconbrief.__version__} (+{REPO_URL})"
ALLOWED_PORTS = {"http": (80,), "https": (443,)}
REDIRECT_CODES = {301, 302, 303, 307, 308}


def _normalize_ip(text: str):
    """Return an ip_address for a literal, unwrapping IPv4-mapped IPv6; else None."""
    try:
        ip = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


@dataclass(frozen=True)
class GuardVerdict:
    """kind: allowed | internal (only non-global addresses) | unresolved | unknown."""

    kind: str
    addresses: tuple[str, ...] = ()
    non_global: tuple[str, ...] = ()
    error: str = ""


class AddressGuard:
    def __init__(self, resolver: DnsResolver | None = None) -> None:
        self.resolver = resolver or DnsResolver()

    def check(self, host: str) -> GuardVerdict:
        literal = _normalize_ip(host)
        if literal is not None:
            if literal.is_global:
                return GuardVerdict("allowed", (str(literal),))
            return GuardVerdict("internal", non_global=(str(literal),))
        good: list[str] = []
        bad: list[str] = []
        states = []
        for rdtype in ("A", "AAAA"):
            result = self.resolver.query(host, rdtype)
            states.append(result.state)
            for text in result.records:
                ip = _normalize_ip(text)
                if ip is None:
                    continue
                (good if ip.is_global else bad).append(str(ip))
        if good:
            return GuardVerdict("allowed", tuple(good), tuple(bad))
        if bad:
            return GuardVerdict("internal", non_global=tuple(bad))
        if Tri.UNKNOWN in states:
            return GuardVerdict("unknown", error="address lookup failed")
        return GuardVerdict("unresolved", error="host has no address records")


@dataclass
class Fetch:
    url: str
    final_url: str = ""
    status: int | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    truncated: bool = False
    peer_cert_der: bytes | None = None
    address: str = ""
    redirects: list[str] = field(default_factory=list)
    error: str | None = None
    internal_addresses: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None

    @property
    def state(self) -> Tri:
        """Got a response: FOUND. Host has no address: ABSENT. Anything else: UNKNOWN."""
        if self.ok:
            return Tri.FOUND
        if self.error == "unresolved":
            return Tri.ABSENT
        return Tri.UNKNOWN

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in reversed(self.headers):
            if key.lower() == name:
                return value
        return None


class HttpClient:
    def __init__(
        self,
        guard: AddressGuard | None = None,
        timeout: float = 10.0,
        max_redirects: int = 5,
        max_bytes: int = 1_000_000,
    ) -> None:
        self.guard = guard or AddressGuard()
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes

    def fetch(self, url: str, headers: dict[str, str] | None = None, max_bytes: int | None = None) -> Fetch:
        result = Fetch(url=url, final_url=url)
        limit = max_bytes or self.max_bytes
        current = url
        for _ in range(self.max_redirects + 1):
            parts = urlsplit(current)
            host = parts.hostname
            if parts.scheme not in ALLOWED_PORTS or not host:
                result.error = "bad_url"
                return result
            port = parts.port or ALLOWED_PORTS[parts.scheme][0]
            if port not in ALLOWED_PORTS[parts.scheme]:
                result.error = "blocked_port"
                return result
            verdict = self.guard.check(host)
            if verdict.kind != "allowed":
                result.error = {"internal": "blocked_address", "unresolved": "unresolved"}.get(
                    verdict.kind, "dns_unknown")
                result.internal_addresses = verdict.non_global
                return result
            result.internal_addresses = verdict.non_global
            self._request_once(result, parts, host, port, verdict.addresses, headers or {}, limit)
            result.final_url = current
            if result.error:
                return result
            location = result.header("location")
            if result.status in REDIRECT_CODES and location:
                result.redirects.append(current)
                current = urljoin(current, location)
                result.body = b""
                continue
            return result
        result.error = "too_many_redirects"
        return result

    def _request_once(self, result: Fetch, parts, host, port, addresses, extra, limit) -> None:
        sock = None
        last_error = "connect_failed"
        for address in addresses:
            try:
                sock = socket.create_connection((address, port), timeout=self.timeout)
                result.address = address
                break
            except socket.timeout:
                last_error = "timeout"
            except OSError:
                last_error = "connect_failed"
        if sock is None:
            result.error = last_error
            return
        try:
            if parts.scheme == "https":
                try:
                    sock, result.peer_cert_der = self._wrap_tls(sock, host)
                except (ssl.SSLError, OSError):
                    result.error = "tls_failed"
                    return
            default_port = ALLOWED_PORTS[parts.scheme][0]
            host_header = host if port == default_port else f"{host}:{port}"
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            request_headers = {"Host": host_header, "User-Agent": USER_AGENT,
                               "Accept": "*/*", "Connection": "close", **extra}
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
            conn.sock = sock  # connect to the address we checked, not to whatever the name resolves to
            try:
                conn.request("GET", path, headers=request_headers)
                response = conn.getresponse()
                result.status = response.status
                result.headers = response.getheaders()
                body = response.read(limit + 1)
                result.truncated = len(body) > limit
                result.body = body[:limit]
            except socket.timeout:
                result.error = "timeout"
            except (OSError, http.client.HTTPException):
                result.error = "read_failed"
            finally:
                conn.close()
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _wrap_tls(self, sock, host: str):
        """TLS with the real hostname as SNI. Verification is off so expired and
        self-signed certificates are still recorded; the certificate is read in binary form."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        wrapped = context.wrap_socket(sock, server_hostname=host)
        return wrapped, wrapped.getpeercert(binary_form=True)
