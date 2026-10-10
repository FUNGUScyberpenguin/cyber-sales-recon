"""Rules from DNS and RDAP: email spoofing, domain registration, dangling DNS."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from reconbrief.models import Finding, Tier, Tri
from reconbrief.rules.common import Index, make_finding, parse_time, shown

MAIL_LENSES = ("red-team", "vciso-program-review")
REGISTRATION_LENSES = ("vciso-program-review", "continuous-exposure-management")
DANGLING_LENSES = ("external-pentest", "continuous-exposure-management", "red-team")
# Providers where an unclaimed resource name can be registered by anyone.
TAKEOVER_SUFFIXES = (".github.io", ".herokuapp.com", ".azurewebsites.net", ".cloudapp.azure.com",
                     ".trafficmanager.net", ".blob.core.windows.net", ".cloudfront.net",
                     ".s3.amazonaws.com", ".elasticbeanstalk.com", ".myshopify.com", ".readthedocs.io",
                     ".netlify.app", ".fastly.net", ".surge.sh", ".ghost.io", ".zendesk.com")


def _mail_enabled(ix: Index) -> bool | None:
    mx = ix.one("dns_record", f"{ix.domain} MX")
    if mx is None or mx.state is Tri.UNKNOWN:
        return None
    if mx.state is Tri.ABSENT:
        return False
    return any(not r.strip().startswith("0 .") for r in mx.data.get("records", []))


def email_spoofing(ix: Index) -> list[Finding]:
    out: list[Finding] = []
    mail = _mail_enabled(ix)
    tier = Tier.ASK if mail else Tier.BACKGROUND
    where = "The domain receives mail." if mail else "The domain has no mail servers listed." if mail is False else ""
    spf, dmarc = ix.one("spf"), ix.one("dmarc")
    if spf is not None and spf.state is Tri.ABSENT:
        out.append(make_finding("email_spoofing", "spf_missing", "No SPF record",
                                f"No SPF record is published for {ix.domain}. {where}".strip(), tier, [spf], MAIL_LENSES))
    elif spf is not None and spf.state is Tri.FOUND:
        record = " ".join(spf.data.get("records", [])).lower()
        if {"all", "+all", "?all"} & set(record.split()):
            out.append(make_finding("email_spoofing", "spf_open", "SPF allows any sender",
                                    f"The SPF record ends in a rule that lets any server send as {ix.domain}: {record[:120]}",
                                    Tier.ASK, [spf], MAIL_LENSES))
    if dmarc is not None and dmarc.state is Tri.ABSENT:
        out.append(make_finding("email_spoofing", "dmarc_missing", "No DMARC record",
                                f"No DMARC record is published for {ix.domain}. {where}".strip(), tier, [dmarc], MAIL_LENSES))
    elif dmarc is not None and dmarc.state is Tri.FOUND:
        record = " ".join(dmarc.data.get("records", [])).lower()
        policy = re.search(r"\bp\s*=\s*(\w+)", record)
        if policy and policy.group(1) == "none":
            out.append(make_finding("email_spoofing", "dmarc_monitor_only", "DMARC is set to monitor only",
                                    "The DMARC policy is p=none: failing mail is reported but still delivered.",
                                    Tier.BACKGROUND, [dmarc], MAIL_LENSES))
    return out


def domain_registration(ix: Index) -> list[Finding]:
    rdap = ix.one("rdap_domain", ix.domain)
    if rdap is None or rdap.state is not Tri.FOUND:
        return []
    d, out = rdap.data, []
    now = datetime.now(timezone.utc)
    if d.get("transfer_lock") is False:
        out.append(make_finding("domain_registration", "no_transfer_lock", "Domain has no transfer lock",
                                f"RDAP status for {ix.domain} shows no transfer-prohibited flag"
                                + (f" (registrar: {d['registrar']})." if d.get("registrar") else "."),
                                Tier.BACKGROUND, [rdap], REGISTRATION_LENSES))
    expires = parse_time(d.get("expires", ""))
    if expires is not None and (expires - now).days <= 30:
        days = (expires - now).days
        when = f"expires in {days} days" if days >= 0 else f"expired {-days} days ago"
        out.append(make_finding("domain_registration", "expiring", "Domain registration is close to expiry",
                                f"The registration for {ix.domain} {when} ({d['expires'][:10]}).",
                                Tier.ASK, [rdap], REGISTRATION_LENSES))
    age = d.get("age_days")
    if isinstance(age, int) and age < 180:
        out.append(make_finding("domain_registration", "recent", "Domain was registered recently",
                                f"{ix.domain} was registered {age} days ago ({d.get('registered', '')[:10]}).",
                                Tier.BACKGROUND, [rdap], REGISTRATION_LENSES))
    return out


def dangling_dns(ix: Index) -> list[Finding]:
    dangling = ix.kind("dangling_cname", Tri.FOUND)
    # Microsoft 365 service names that CNAME to Microsoft are never findings.
    dangling = [e for e in dangling if e.subject not in ix.m365_microsoft]
    if not dangling:
        return []
    claimable = [e for e in dangling if str(e.data.get("target", "")).endswith(TAKEOVER_SUFFIXES)]
    tier = Tier.LEAD if claimable else Tier.ASK
    shown_hosts = shown(f"{e.subject} -> {e.data.get('target', '')}" for e in (claimable or dangling))
    detail = (f"{len(dangling)} hostname(s) point at a name that does not exist: {shown_hosts}."
              + (" The target is on a service where anyone can register the missing name." if claimable else ""))
    return [make_finding("dangling_dns", "cname", "DNS points at a name that does not exist", detail, tier,
                         dangling, DANGLING_LENSES)]
