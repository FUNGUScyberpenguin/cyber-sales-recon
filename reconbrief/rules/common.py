"""Helpers shared by the rules. Rules read evidence and return findings; they never make a request."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

from reconbrief.models import Evidence, Finding, Tier, Tri

TIER_ORDER = {Tier.LEAD: 0, Tier.ASK: 1, Tier.BACKGROUND: 2}


class Index:
    """Evidence grouped the ways the rules ask for it."""

    def __init__(self, evidence: list[Evidence], domain: str = "") -> None:
        self.evidence = evidence
        self.domain = domain
        self.by_kind: dict[str, list[Evidence]] = {}
        for e in evidence:
            self.by_kind.setdefault(e.kind, []).append(e)
        self.pages = {e.subject: e for e in self.kind("web_page") if e.source == "page_loader"}
        self.host_dns = {e.subject: e for e in self.kind("host_dns")}
        self.m365_microsoft = {e.subject for e in self.kind("m365_name") if e.data.get("points_to_microsoft")}

    def kind(self, kind: str, state: Tri | None = None) -> list[Evidence]:
        items = self.by_kind.get(kind, [])
        return [e for e in items if state is None or e.state is state]

    def one(self, kind: str, subject: str | None = None) -> Evidence | None:
        for e in self.by_kind.get(kind, []):
            if subject is None or e.subject == subject:
                return e
        return None

    def live_pages(self) -> list[Evidence]:
        """Pages that loaded and count as a real host: a wildcard host counts only if its page differs from the wildcard's."""
        return [p for p in self.pages.values() if p.state is Tri.FOUND and p.data.get("live") is True
                and p.subject not in self.m365_microsoft]

    def page_ok(self, host: str) -> bool:
        p = self.pages.get(host)
        return bool(p and p.state is Tri.FOUND and p.data.get("live") is True and host not in self.m365_microsoft)


def header(page: Evidence, name: str) -> str | None:
    for k, v in page.data.get("headers", []):
        if k.lower() == name:
            return v
    return None


def shown(items, limit: int = 5) -> str:
    items = list(items)
    text = ", ".join(str(i) for i in items[:limit])
    return text + (f" and {len(items) - limit} more" if len(items) > limit else "")


def ids(evidence: list[Evidence]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(e.id for e in evidence))


def make_finding(rule: str, key: str, title: str, detail: str, tier: Tier, evidence: list[Evidence],
                 lenses: tuple[str, ...]) -> Finding:
    return Finding(id=f"{rule}:{key}", rule=rule, title=title, detail=detail, tier=tier,
                   evidence_ids=ids(evidence), lenses=lenses)


def parse_time(text: str) -> datetime | None:
    try:
        when = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def all_non_global(addresses) -> bool:
    """True when there is at least one address and none of them is globally routable."""
    parsed = []
    for text in addresses:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            continue
        parsed.append(ipaddress.IPv4Address(ip.ipv4_mapped) if getattr(ip, "ipv4_mapped", None) else ip)
    return bool(parsed) and not any(ip.is_global for ip in parsed)


def label_tokens(host: str, domain: str) -> set[str]:
    """Words in the part of a hostname left of the prospect's domain: 'dev-api2.acme.com' gives {dev, api}."""
    prefix = host[: -len(domain)] if domain and host.endswith(domain) else host
    return {t for t in re.split(r"[-_.\d]+", prefix.lower()) if t}
