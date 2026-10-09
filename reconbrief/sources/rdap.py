"""RDAP: registrar, dates, nameservers, transfer lock, and a registrant org when it isn't redacted."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from reconbrief.models import Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.common import get_json, make_evidence

RDAP_URL = "https://rdap.org/domain/{d}"
TRANSFER_LOCKS = {"clienttransferprohibited", "servertransferprohibited"}
REDACTION_WORDS = ("redacted", "privacy", "withheld", "not disclosed", "data protected",
                   "whoisguard", "domains by proxy", "contact privacy")


def normalize_status(status: str) -> str:
    """Lowercase and drop spaces, hyphens, underscores: 'client transfer prohibited' == 'clientTransferProhibited'."""
    return re.sub(r"[\s_-]+", "", str(status).lower())


def _vcard(entity: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "org"):
            value = item[3]
            out.setdefault(item[0], " ".join(value) if isinstance(value, list) else str(value))
    return out


def _entities(entities: list, role: str):
    for entity in entities or []:
        if role in entity.get("roles", []):
            yield entity
        yield from _entities(entity.get("entities", []), role)


def _parse_date(text: str) -> datetime | None:
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


class Rdap:
    name = "rdap"
    stage = 1

    def run(self, ctx: Context) -> SourceResult:
        result = get_json(ctx, RDAP_URL.format(d=ctx.domain))
        if result.state is Tri.UNKNOWN:
            ev = make_evidence(self.name, "rdap_domain", ctx.domain, Tri.UNKNOWN, error=result.error)
            return SourceResult(Health.FAILED, [ev], result.error)
        if result.state is Tri.ABSENT:
            return SourceResult(Health.OK, [make_evidence(self.name, "rdap_domain", ctx.domain, Tri.ABSENT)])
        doc = result.data if isinstance(result.data, dict) else {}
        statuses = sorted({normalize_status(s) for s in doc.get("status", [])})
        events = {e.get("eventAction"): e.get("eventDate", "") for e in doc.get("events", [])}
        registered = events.get("registration", "")
        expires = events.get("expiration", "")
        age_days = None
        if (reg := _parse_date(registered)) is not None:
            age_days = (datetime.now(timezone.utc) - reg).days
        registrar = next((_vcard(e).get("fn", "") for e in _entities(doc.get("entities"), "registrar")), "")
        registrant_org = ""
        for entity in _entities(doc.get("entities"), "registrant"):
            card = _vcard(entity)
            org = card.get("org") or card.get("fn", "")
            if org and not any(w in org.lower() for w in REDACTION_WORDS):
                registrant_org = org
                break
        nameservers = sorted(n.get("ldhName", "").lower().rstrip(".") for n in doc.get("nameservers", []))
        ev = make_evidence(
            self.name, "rdap_domain", ctx.domain, Tri.FOUND,
            statuses=statuses, transfer_lock=bool(TRANSFER_LOCKS & set(statuses)) if statuses else None,
            registered=registered, expires=expires, last_changed=events.get("last changed", ""),
            age_days=age_days, registrar=registrar, registrant_org=registrant_org,
            nameservers=[n for n in nameservers if n],
        )
        return SourceResult(Health.OK, [ev])
