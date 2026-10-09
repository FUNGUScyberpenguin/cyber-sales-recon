"""Domain registration data from RDAP, found through the IANA bootstrap file."""
from __future__ import annotations

from reconbrief.models import Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.base import make_evidence

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
REDACTION_WORDS = ("redacted", "privacy", "withheld", "data protected", "not disclosed", "whoisguard", "proxy")


def normalize_status(text: str) -> str:
    """'client transfer prohibited', 'clientTransferProhibited' and 'client_transfer-prohibited' all match."""
    return "".join(ch for ch in text.lower() if ch not in " -_")


def _vcard_field(entity: dict, field: str) -> str:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == field and len(item) > 3:
            return str(item[3] if not isinstance(item[3], list) else " ".join(map(str, item[3]))).strip()
    return ""


def _redacted(text: str) -> bool:
    low = text.lower()
    return not text or any(w in low for w in REDACTION_WORDS)


def parse_domain(doc: dict) -> dict:
    statuses = [str(s) for s in doc.get("status") or []]
    norm = {normalize_status(s) for s in statuses}
    events = {str(e.get("eventAction", "")).lower(): str(e.get("eventDate", ""))
              for e in doc.get("events") or []}
    registrar = registrant_org = ""
    for entity in doc.get("entities") or []:
        roles = [str(r).lower() for r in entity.get("roles") or []]
        if "registrar" in roles and not registrar:
            registrar = _vcard_field(entity, "fn")
        if "registrant" in roles and not registrant_org:
            org = _vcard_field(entity, "org") or _vcard_field(entity, "fn")
            registrant_org = "" if _redacted(org) else org
    return {
        "statuses": sorted(norm),
        "statuses_raw": statuses,
        "transfer_lock": bool(norm & {"clienttransferprohibited", "servertransferprohibited"}),
        "delete_lock": bool(norm & {"clientdeleteprohibited", "serverdeleteprohibited"}),
        "update_lock": bool(norm & {"clientupdateprohibited", "serverupdateprohibited"}),
        "registered": events.get("registration", ""),
        "expires": events.get("expiration", ""),
        "last_changed": events.get("last changed", ""),
        "registrar": registrar,
        "registrant_org": registrant_org,
        "nameservers": sorted(str(n.get("ldhName", "")).lower() for n in doc.get("nameservers") or []),
        "dnssec_signed": bool((doc.get("secureDNS") or {}).get("delegationSigned")),
    }


class Rdap:
    name = "rdap"
    stage = 1

    def run(self, ctx: Context) -> SourceResult:
        labels = ctx.domain.split(".")
        boot = ctx.api.get(BOOTSTRAP_URL)
        services = boot.json() if boot.ok else None
        if not isinstance(services, dict):
            return self._unknown(ctx, f"IANA bootstrap {boot.why()}")
        base = None
        for tlds, urls in services.get("services", []):
            if labels[-1] in tlds and urls:
                base = next((u for u in urls if u.startswith("https://")), None)
                break
        if base is None:
            return self._unknown(ctx, f"no RDAP server listed for .{labels[-1]}")
        base = base if base.endswith("/") else base + "/"
        # A subdomain has no record of its own, so step toward the parent, down to two labels.
        for start in range(0, max(1, len(labels) - 1)):
            queried = ".".join(labels[start:])
            r = ctx.api.get(f"{base}domain/{queried}", {"Accept": "application/rdap+json"})
            if r.ok:
                doc = r.json()
                if not isinstance(doc, dict):
                    return self._unknown(ctx, "unreadable RDAP response")
                data = parse_domain(doc)
                ev = make_evidence(self.name, "rdap_domain", ctx.domain, Tri.FOUND, queried=queried, **data)
                return SourceResult(Health.OK, [ev])
            if r.status != 404:
                return self._unknown(ctx, f"RDAP {r.why()}")
        ev = make_evidence(self.name, "rdap_domain", ctx.domain, Tri.ABSENT, queried=ctx.domain)
        return SourceResult(Health.OK, [ev], "RDAP says the domain is not registered")

    def _unknown(self, ctx: Context, why: str) -> SourceResult:
        ev = make_evidence(self.name, "rdap_domain", ctx.domain, Tri.UNKNOWN, error=why)
        return SourceResult(Health.FAILED, [ev], why)
