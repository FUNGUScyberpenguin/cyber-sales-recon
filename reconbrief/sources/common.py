"""Helpers shared by the discovery sources."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from reconbrief.http import Fetch
from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context

JSON_LIMIT = 25_000_000
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
TRANSIENT = {429, 500, 502, 503, 504}


def evidence_id(source: str, kind: str, subject: str) -> str:
    return f"{source}:{kind}:{subject}"


def make_evidence(source: str, kind: str, subject: str, state: Tri, **data: Any) -> Evidence:
    return Evidence(evidence_id(source, kind, subject), source, kind, subject, state, data)


def normalize_host(name: str) -> str | None:
    """Lowercase, drop a wildcard prefix and a trailing dot. None if it isn't a hostname."""
    host = name.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    return host if HOST_RE.match(host) else None


def in_scope(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


@dataclass
class JsonResult:
    state: Tri
    data: Any = None
    status: int | None = None
    error: str = ""
    truncated: bool = False


def get_json(ctx: Context, url: str, headers: dict[str, str] | None = None) -> JsonResult:
    """GET a JSON document. 404 is ABSENT; any failure, throttle, or bad body is UNKNOWN."""
    fetch: Fetch = ctx.http.fetch(url, headers=headers, max_bytes=JSON_LIMIT)
    if not fetch.ok:
        return JsonResult(Tri.UNKNOWN, error=fetch.error or "no response")
    if fetch.status == 404:
        return JsonResult(Tri.ABSENT, status=404)
    if fetch.status != 200:
        return JsonResult(Tri.UNKNOWN, status=fetch.status, error=f"HTTP {fetch.status}")
    if fetch.truncated:
        return JsonResult(Tri.UNKNOWN, status=200, error="response too large", truncated=True)
    try:
        return JsonResult(Tri.FOUND, json.loads(fetch.body), 200)
    except ValueError:
        return JsonResult(Tri.UNKNOWN, status=200, error="response was not JSON")


def health_from(states: list[Tri]) -> Health:
    """OK when every check was answered, FAILED when none was, else PARTIAL."""
    if not states or all(s is Tri.UNKNOWN for s in states):
        return Health.FAILED
    return Health.PARTIAL if Tri.UNKNOWN in states else Health.OK
