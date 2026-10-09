"""Test doubles: a scripted DNS resolver and a fake HTTP client that serves saved responses."""
from pathlib import Path

from reconbrief.http import Fetch
from reconbrief.models import Tri
from reconbrief.pipeline import Context
from reconbrief.resolver import DnsResolver, DnsResult

RECORDED = Path(__file__).parent / "fixtures" / "recorded"


def recorded(name: str) -> bytes:
    return (RECORDED / name).read_bytes()


class ScriptedDns(DnsResolver):
    """answers: {(name, type): DnsResult | list[str]}. Unlisted lookups are NXDOMAIN (absent)."""

    def __init__(self, answers=None, unknown=()):
        super().__init__(nameservers=["192.0.2.53"])
        self.answers = {k: v for k, v in (answers or {}).items()}
        self.unknown = set(unknown)  # (name, type) pairs that time out
        self.asked = []

    def query(self, name, rdtype):
        key = (name.lower().rstrip("."), rdtype)
        self.asked.append(key)
        if key in self.unknown:
            return DnsResult(Tri.UNKNOWN, error="timeout")
        value = self.answers.get(key)
        if value is None:
            return DnsResult(Tri.ABSENT, error="NXDOMAIN")
        if isinstance(value, DnsResult):
            return value
        return DnsResult(Tri.FOUND, tuple(value), ttl=300)


def response(status=200, body=b"", error=None, headers=None, **extra):
    return Fetch(url=extra.pop("url", ""), final_url=extra.pop("final_url", ""), status=None if error else status,
                 body=body, error=error, headers=list(headers or []), **extra)


class FakeHttp:
    """routes: list of (url prefix, Fetch | bytes | callable(url) -> Fetch). First prefix match wins."""

    def __init__(self, routes=()):
        self.routes = list(routes)
        self.requested = []

    def fetch(self, url, headers=None, max_bytes=None):
        self.requested.append(url)
        for prefix, value in self.routes:
            if url.startswith(prefix):
                if callable(value):
                    return value(url)
                if isinstance(value, bytes):
                    return response(200, value)
                return value
        return response(error="connect_failed")


def make_ctx(domain="example.com", dns=None, http=None, evidence=()):
    ctx = Context(domain, dns or ScriptedDns(), http or FakeHttp())
    ctx.evidence.extend(evidence)
    return ctx
