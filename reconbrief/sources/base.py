"""Small helpers shared by the discovery sources."""
from __future__ import annotations

import re
from typing import Any

from reconbrief.models import Evidence, Tri, evidence_id

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")


def make_evidence(source: str, kind: str, subject: str, state: Tri, **data: Any) -> Evidence:
    return Evidence(evidence_id(source, kind, subject), source, kind, subject, state, data)


def clean_hostname(text: str) -> str | None:
    """Lowercase a hostname and drop wildcards, ports, dots and junk. None if it is not one."""
    name = text.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not _HOST_RE.match(name):
        return None
    return name


def under(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)
