"""Data models. Evidence is what a source saw; a finding is a rule's reading of evidence."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

LENSES = (
    "external-pentest",
    "web-app-api",
    "continuous-exposure-management",
    "red-team",
    "ai-red-teaming",
    "vciso-program-review",
)


class Tri(str, Enum):
    """Result of any check. A failed lookup is UNKNOWN, never ABSENT."""

    FOUND = "found"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class Health(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class Tier(str, Enum):
    LEAD = "lead"
    ASK = "ask"
    BACKGROUND = "background"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Evidence:
    id: str
    source: str
    kind: str
    subject: str
    state: Tri
    data: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "source": self.source, "kind": self.kind,
            "subject": self.subject, "state": self.state.value,
            "data": self.data, "observed_at": self.observed_at,
        }


@dataclass(frozen=True)
class Finding:
    id: str
    rule: str
    title: str
    detail: str
    tier: Tier
    evidence_ids: tuple[str, ...]
    lenses: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.evidence_ids:
            raise ValueError("a finding must cite at least one evidence id")
        bad = [lens for lens in self.lenses if lens not in LENSES]
        if bad:
            raise ValueError(f"unknown lens: {bad}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "rule": self.rule, "title": self.title,
            "detail": self.detail, "tier": self.tier.value,
            "evidence_ids": list(self.evidence_ids), "lenses": list(self.lenses),
        }


@dataclass(frozen=True)
class SourceHealth:
    source: str
    status: Health
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "status": self.status.value, "detail": self.detail}
