from pathlib import Path

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rrset

from reconbrief.models import Tri
from reconbrief.resolver import DnsResolver

FIXTURE = Path(__file__).parent / "fixtures" / "recorded" / "txt_40_records.wire"


def make_query():
    return dns.message.make_query("example.com", "TXT")


def resolver(transport):
    return DnsResolver(nameservers=["192.0.2.53"], transport=transport, timeout=0.1)


def test_timeout_yields_unknown_not_absent():
    calls = []

    def transport(q, server, timeout, tcp):
        calls.append(tcp)
        raise dns.exception.Timeout()

    result = resolver(transport).query("example.com", "TXT")
    assert result.state is Tri.UNKNOWN
    assert calls.count(False) == 3 and calls[-1] is True  # UDP retries, then TCP


def test_servfail_is_unknown():
    def transport(q, server, timeout, tcp):
        r = dns.message.make_response(q)
        r.set_rcode(dns.rcode.SERVFAIL)
        return r

    assert resolver(transport).query("example.com", "A").state is Tri.UNKNOWN


def test_nxdomain_and_empty_answer_are_absent():
    def nx(q, server, timeout, tcp):
        r = dns.message.make_response(q)
        r.set_rcode(dns.rcode.NXDOMAIN)
        return r

    def empty(q, server, timeout, tcp):
        return dns.message.make_response(q)

    assert resolver(nx).query("example.com", "A").state is Tri.ABSENT
    assert resolver(empty).query("example.com", "A").state is Tri.ABSENT


def test_timeout_then_answer_retries_and_succeeds():
    seen = []

    def transport(q, server, timeout, tcp):
        seen.append(tcp)
        if len(seen) == 1:
            raise dns.exception.Timeout()
        r = dns.message.make_response(q)
        r.answer.append(dns.rrset.from_text("example.com.", 60, "IN", "A", "93.184.216.34"))
        return r

    result = resolver(transport).query("example.com", "A")
    assert result.state is Tri.FOUND and result.records == ("93.184.216.34",)


def test_recorded_40_record_txt_answer_parses_after_tcp_retry():
    full = dns.message.from_wire(FIXTURE.read_bytes())
    seen = []

    def transport(q, server, timeout, tcp):
        seen.append(tcp)
        if not tcp:  # UDP answer is truncated, so the resolver must retry over TCP
            r = dns.message.make_response(q)
            r.flags |= dns.flags.TC
            return r
        return full

    result = resolver(transport).query("example.com", "TXT")
    assert seen == [False, True]
    assert result.state is Tri.FOUND
    assert len(result.records) == 40
    assert "v=spf1 include:_spf0.example.net ~all" in result.records
    assert any(len(r) > 255 for r in result.records)  # multi-string record joined into one value


def test_servfail_from_one_nameserver_falls_through_to_the_next():
    def transport(q, server, timeout, tcp):
        r = dns.message.make_response(q)
        if server == "192.0.2.53":
            r.set_rcode(dns.rcode.SERVFAIL)
        else:
            r.answer.append(dns.rrset.from_text("example.com.", 60, "IN", "A", "93.184.216.34"))
        return r

    result = DnsResolver(nameservers=["192.0.2.53", "192.0.2.54"], transport=transport).query("example.com", "A")
    assert result.state is Tri.FOUND
