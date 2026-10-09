"""Fakes for discovery tests: no live websites, no live DNS."""
import json
from pathlib import Path

import dns.exception
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

from reconbrief.api import ApiClient
from reconbrief.http import AddressGuard, HttpClient
from reconbrief.pipeline import Context
from reconbrief.resolver import DnsResolver

FIX = Path(__file__).parent / "fixtures" / "discovery"


def fixture(name: str) -> bytes:
    return (FIX / name).read_bytes()


class FakeApi:
    """routes: list of (url substring, response or list of responses). A response is
    (status, bytes) or an exception to raise. A list is consumed in order, last one repeats."""

    def __init__(self, routes):
        self.routes = [(k, list(v) if isinstance(v, list) else [v]) for k, v in routes]
        self.calls: list[str] = []

    def __call__(self, url, headers, timeout):
        self.calls.append(url)
        for key, queue in self.routes:
            if key in url:
                item = queue.pop(0) if len(queue) > 1 else queue[0]
                if isinstance(item, Exception):
                    raise item
                return item[0], (item[2] if len(item) > 2 else {}), item[1]
        return 404, {}, b"not found"

    def client(self) -> ApiClient:
        return ApiClient(transport=self, sleep=lambda s: None, backoff=0)


def ok(name: str):
    return 200, fixture(name)


class FakeZone:
    """zone: {(name, type): [rdata text]}. Unknown names are NXDOMAIN; known names with no
    record of the asked type are empty. fail: {(name, type)} raise a timeout."""

    def __init__(self, zone, fail=(), wildcard_a=None, domain="example.com"):
        self.zone = {(n.rstrip(".").lower(), t): v for (n, t), v in zone.items()}
        self.names = {n for n, _ in self.zone}
        self.fail = {(n.rstrip(".").lower(), t) for n, t in fail}
        self.wildcard_a, self.domain = wildcard_a, domain

    def __call__(self, q, server, timeout, tcp):
        name = q.question[0].name.to_text().rstrip(".").lower()
        rdtype = dns.rdatatype.to_text(q.question[0].rdtype)
        if (name, rdtype) in self.fail:
            raise dns.exception.Timeout()
        r = dns.message.make_response(q)
        values = self.zone.get((name, rdtype))
        if values is None and self.wildcard_a and rdtype == "A" and name.endswith("." + self.domain) \
                and name not in self.names:
            values = [self.wildcard_a]
        if values:
            r.answer.append(dns.rrset.from_text(name + ".", 300, "IN", rdtype, *values))
        elif name not in self.names and not (self.wildcard_a and name.endswith("." + self.domain)):
            r.set_rcode(dns.rcode.NXDOMAIN)
        return r


def make_ctx(zone=None, routes=(), domain="example.com", **zone_kwargs):
    resolver = DnsResolver(nameservers=["192.0.2.53"], transport=FakeZone(zone or {}, domain=domain, **zone_kwargs),
                           timeout=0.1)
    api = FakeApi(routes)
    return Context(domain, resolver, HttpClient(AddressGuard(resolver)), api=api.client()), api
