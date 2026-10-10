"""Pick the offering that best fits the findings, from the user's own list. Never invents an offering."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from reconbrief.models import LENSES, Finding, Tier

WEIGHT = {Tier.LEAD: 3, Tier.ASK: 2, Tier.BACKGROUND: 1}
MAX_REASONS = 3


class ProfileError(ValueError):
    pass


@dataclass(frozen=True)
class Offering:
    name: str
    lenses: tuple[str, ...]


def load_offerings(path: Path) -> list[Offering]:
    """Read the offerings from the firm profile file. Each maps to one or more of the six lenses."""
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise ProfileError(f"profile not readable: {exc}") from exc
    items = doc.get("offerings") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise ProfileError("profile has no offerings list")
    out = []
    for item in items:
        name = str(item.get("name", "")).strip() if isinstance(item, dict) else ""
        lenses = tuple(item.get("lenses", [])) if isinstance(item, dict) else ()
        bad = [lens for lens in lenses if lens not in LENSES]
        if not name or bad:
            raise ProfileError(f"offering {name or item!r} has no name or an unknown lens {bad}")
        out.append(Offering(name, lenses))
    return out


def recommend(offerings: list[Offering], findings: list[Finding]) -> dict | None:
    """The offering whose lenses the findings touch most, weighted by tier. None if nothing matches."""
    best: tuple[int, int, Offering, list[Finding]] | None = None
    for position, offering in enumerate(offerings):
        matched = [f for f in findings if set(f.lenses) & set(offering.lenses)]
        score = sum(WEIGHT[f.tier] for f in matched)
        if score and (best is None or score > best[0]):
            best = (score, position, offering, matched)
    if best is None:
        return None
    score, _, offering, matched = best
    top = sorted(matched, key=lambda f: (-WEIGHT[f.tier], f.id))[:MAX_REASONS]
    return {"offering": offering.name, "lenses": list(offering.lenses), "score": score,
            "finding_ids": [f.id for f in top]}
