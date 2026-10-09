"""Company profile from Wikidata, GLEIF, and EDGAR, matched only on trusted names.

Trusted names: the user's hint, the homepage og:site_name, and an unredacted RDAP registrant org.
A name is never searched from page text or a hostname. A GLEIF or EDGAR entity is accepted only
with a second agreeing signal: its website is the prospect's domain, or its city is the city of
an entity already confirmed by domain. An entity without that never sets legal_name.
"""
from __future__ import annotations

import re
from urllib.parse import quote, urlsplit

from reconbrief.models import Evidence, Health, Tri
from reconbrief.pipeline import Context, SourceResult
from reconbrief.sources.common import JsonResult, get_json, health_from, in_scope, make_evidence

WIKIDATA_SEARCH = ("https://www.wikidata.org/w/api.php?action=wbsearchentities&search={q}"
                   "&language=en&type=item&limit=50&format=json")
WIKIDATA_ENTITY = "https://www.wikidata.org/wiki/Special:EntityData/{id}.json"
WIKIDATA_LABELS = "https://www.wikidata.org/w/api.php?action=wbgetentities&ids={ids}&props=labels&languages=en&format=json"
GLEIF_URL = "https://api.gleif.org/api/v1/lei-records?filter%5Bfulltext%5D={q}&page%5Bsize%5D=100&page%5Bnumber%5D={page}"
EDGAR_TICKERS = "https://www.sec.gov/files/company_tickers.json"
EDGAR_SUBMISSIONS = "https://data.sec.gov/submissions/CIK{cik:010d}.json"
MAX_NAMES = 2
MAX_WIKIDATA_CANDIDATES = 3
MAX_PAGES = 5
_SUFFIXES = re.compile(r"\b(?:inc|incorporated|llc|ltd|limited|corp|corporation|co|company|plc|gmbh|sa|ag|bv|nv|lp|llp)\b")


def norm_name(name: str) -> str:
    """Compare names without case, punctuation, a leading 'the', or a legal suffix."""
    text = re.sub(r"[^a-z0-9& ]+", " ", name.lower().replace("&", " and "))
    text = re.sub(r"^the ", "", " ".join(text.split()))
    return " ".join(_SUFFIXES.sub(" ", text).split())


def norm_city(city: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9 ]+", " ", city.lower()).split())


def domain_of(url: str) -> str:
    host = (urlsplit(url if "//" in url else "//" + url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def same_site(url: str, domain: str) -> bool:
    host = domain_of(url)
    return bool(host) and (in_scope(host, domain) or in_scope(domain, host))


def trusted_names(ctx: Context) -> list[dict]:
    raw: list[tuple[str, str]] = []
    if ctx.company_hint.strip():
        raw.append((ctx.company_hint.strip(), "user hint"))
    for e in ctx.evidence:
        if e.kind == "web_page" and e.state is Tri.FOUND and e.data.get("og_site_name") \
                and e.subject in (ctx.domain, f"www.{ctx.domain}"):
            raw.append((e.data["og_site_name"], f"og:site_name on {e.subject}"))
        if e.kind == "rdap_domain" and e.state is Tri.FOUND and e.data.get("registrant_org"):
            raw.append((e.data["registrant_org"], "RDAP registrant"))
    out, seen = [], set()
    for name, source in raw:
        key = norm_name(name)
        if key and key not in seen:
            seen.add(key)
            out.append({"name": name, "source": source})
    return out[:MAX_NAMES]


def _claim(claims: dict, prop: str):
    for c in claims.get(prop, []):
        value = (c.get("mainsnak", {}).get("datavalue") or {}).get("value")
        if value is not None:
            return value
    return None


def endpoint_json(ctx: Context, url: str):
    """get_json for an API endpoint that always exists: a 404 means the endpoint moved, not 'no match'."""
    result = get_json(ctx, url)
    if result.state is Tri.ABSENT:
        return JsonResult(Tri.UNKNOWN, status=404, error="HTTP 404 from the lookup service")
    return result


def wikidata_search(ctx: Context, name: str):
    """(hits whose label is the name, error). Reads every page of results, up to MAX_PAGES."""
    hits, offset = [], 0
    for _ in range(MAX_PAGES):
        page = endpoint_json(ctx, WIKIDATA_SEARCH.format(q=quote(name)) + (f"&continue={offset}" if offset else ""))
        if page.state is not Tri.FOUND or not isinstance(page.data, dict):
            return None, page.error or "unreadable response"
        hits += [h for h in page.data.get("search", []) if norm_name(h.get("label", "")) == norm_name(name)]
        if "search-continue" not in page.data:
            return hits, ""
        offset = page.data["search-continue"]
    return (hits, "") if hits else (None, f"more than {MAX_PAGES} pages of results")


def wikidata_lookup(ctx: Context, name: str):
    """(state, candidates, error). A candidate matches the name; confirmed means its website is the domain."""
    hits, error = wikidata_search(ctx, name)
    if hits is None:
        return Tri.UNKNOWN, [], error
    candidates, errors = [], []
    for hit in hits[:MAX_WIKIDATA_CANDIDATES]:
        entity = get_json(ctx, WIKIDATA_ENTITY.format(id=hit["id"]))
        if entity.state is not Tri.FOUND:
            errors.append(entity.error or "entity not found")
            continue
        claims = entity.data.get("entities", {}).get(hit["id"], {}).get("claims", {})
        site = _claim(claims, "P856")
        hq = _claim(claims, "P159")
        hq_id = hq.get("id") if isinstance(hq, dict) else None
        inception = _claim(claims, "P571")
        employees = _claim(claims, "P1128")
        candidates.append({
            "source": "wikidata", "id": hit["id"], "name": hit.get("label", ""),
            "website": site if isinstance(site, str) else "", "hq_id": hq_id, "city": "",  # city is read once confirmed
            "inception_year": (inception or {}).get("time", "")[1:5] if isinstance(inception, dict) else "",
            "employees": (employees or {}).get("amount", "").lstrip("+") if isinstance(employees, dict) else "",
            "lei": _claim(claims, "P1278") or "", "cik": _claim(claims, "P5531") or "",
        })
    state = Tri.FOUND if candidates else Tri.UNKNOWN if errors else Tri.ABSENT
    return state, candidates, "; ".join(errors)


def wikidata_city(ctx: Context, hq_id: str) -> str:
    labels = get_json(ctx, WIKIDATA_LABELS.format(ids=hq_id))
    if labels.state is not Tri.FOUND:
        return ""
    return ((labels.data.get("entities", {}).get(hq_id, {}).get("labels", {}) or {}).get("en") or {}).get("value", "")


def edgar_lookup(ctx: Context, name: str):
    tickers = endpoint_json(ctx, EDGAR_TICKERS)
    if tickers.state is not Tri.FOUND:
        return Tri.UNKNOWN, [], tickers.error
    rows = tickers.data.values() if isinstance(tickers.data, dict) else []
    matches = [r for r in rows if norm_name(str(r.get("title", ""))) == norm_name(name)]
    candidates, errors = [], []
    for row in matches[:MAX_WIKIDATA_CANDIDATES]:
        sub = get_json(ctx, EDGAR_SUBMISSIONS.format(cik=int(row["cik_str"])))
        if sub.state is not Tri.FOUND:
            errors.append(sub.error or "submissions not found")
            continue
        d = sub.data
        business = (d.get("addresses") or {}).get("business") or {}
        candidates.append({
            "source": "edgar", "id": str(int(row["cik_str"])), "name": d.get("name", row.get("title", "")),
            "website": d.get("website", "") or "", "city": business.get("city", "") or "",
            "state": business.get("stateOrCountry", "") or "", "tickers": d.get("tickers", []),
            "sic_description": d.get("sicDescription", ""),
        })
    state = Tri.FOUND if candidates else Tri.UNKNOWN if errors else Tri.ABSENT
    return state, candidates, "; ".join(errors)


def gleif_lookup(ctx: Context, name: str):
    """Reads every page of the full-text results. Names that do not match are dropped."""
    candidates, complete = [], False
    for page_no in range(1, MAX_PAGES + 1):
        result = endpoint_json(ctx, GLEIF_URL.format(q=quote(name), page=page_no))
        if result.state is not Tri.FOUND or not isinstance(result.data, dict):
            return Tri.UNKNOWN, [], result.error or "unreadable response"
        for rec in result.data.get("data", []):
            attrs = rec.get("attributes", {})
            entity = attrs.get("entity", {})
            legal = (entity.get("legalName") or {}).get("name", "")
            if norm_name(legal) != norm_name(name):
                continue
            address = entity.get("headquartersAddress") or entity.get("legalAddress") or {}
            candidates.append({
                "source": "gleif", "id": attrs.get("lei", ""), "name": legal, "city": address.get("city", "") or "",
                "country": address.get("country", "") or "", "status": entity.get("status", ""),
            })
        pagination = (result.data.get("meta") or {}).get("pagination") or {}
        if not pagination.get("nextPage"):
            complete = True
            break
    if candidates:
        return Tri.FOUND, candidates, "" if complete else f"read the first {MAX_PAGES} pages only"
    if not complete:  # a match could sit on a page we did not read
        return Tri.UNKNOWN, [], f"more than {MAX_PAGES} pages of results"
    return Tri.ABSENT, [], ""


class CompanyProfile:
    name = "company"
    stage = 4

    def run(self, ctx: Context) -> SourceResult:
        names = trusted_names(ctx)
        if not names:
            return SourceResult(Health.SKIPPED, [], "no trusted company name (no hint, og:site_name, or RDAP registrant)")
        evidence: list[Evidence] = []
        lookup_states: list[Tri] = []
        confirmed: list[dict] = []
        for trusted in names:
            wd_state, wd, wd_err = wikidata_lookup(ctx, trusted["name"])
            for cand in wd:
                if same_site(cand["website"], ctx.domain):
                    cand["signals"] = ["domain"]
                    cand["city"] = wikidata_city(ctx, cand["hq_id"]) if cand.get("hq_id") else ""
                    confirmed.append(cand)
                else:
                    cand["signals"] = []
            ed_state, ed, ed_err = edgar_lookup(ctx, trusted["name"])
            cities = {norm_city(c["city"]) for c in confirmed if c.get("city")}
            for cand in ed:
                if same_site(cand["website"], ctx.domain):
                    cand["signals"] = ["domain"]
                elif cand["city"] and norm_city(cand["city"]) in cities:
                    cand["signals"] = ["city"]
                else:
                    cand["signals"] = []
                if cand["signals"]:
                    confirmed.append(cand)
            cities = {norm_city(c["city"]) for c in confirmed if c.get("city")}
            gl_state, gl, gl_err = gleif_lookup(ctx, trusted["name"])
            for cand in gl:
                agrees = bool(cand["city"]) and norm_city(cand["city"]) in cities
                cand["signals"] = ["city"] if agrees else []
                if agrees:
                    confirmed.append(cand)
            for source, state, cands, err in (("wikidata", wd_state, wd, wd_err), ("edgar", ed_state, ed, ed_err),
                                               ("gleif", gl_state, gl, gl_err)):
                lookup_states.append(state)
                evidence.append(make_evidence(
                    self.name, "company_lookup", f"{source}:{norm_name(trusted['name'])}", state,
                    lookup=source, searched_name=trusted["name"], name_source=trusted["source"], error=err,
                    candidates=[{"id": c["id"], "name": c["name"], "corroborated": bool(c["signals"]),
                                 "signals": c["signals"], "city": c.get("city", "")} for c in cands]))
        evidence.append(self._profile(ctx, names, confirmed, lookup_states))
        return SourceResult(health_from(lookup_states), evidence,
                            "" if Tri.UNKNOWN not in lookup_states else
                            f"{lookup_states.count(Tri.UNKNOWN)} of {len(lookup_states)} lookups not checked")

    def _profile(self, ctx: Context, names, confirmed: list[dict], states: list[Tri]) -> Evidence:
        by_source = {c["source"]: c for c in reversed(confirmed)}
        legal = by_source.get("edgar") or by_source.get("gleif")  # Wikidata labels are display names, not legal names
        wd = by_source.get("wikidata")
        cities = [c["city"] for c in (wd, by_source.get("edgar"), by_source.get("gleif")) if c and c.get("city")]
        data = {
            "trusted_names": names,
            "legal_name": legal["name"] if legal else None,
            "legal_name_source": legal["source"] if legal else None,
            "hq_city": cities[0] if cities else None,
            "lei": (by_source.get("gleif") or {}).get("id") or (wd or {}).get("lei") or None,
            "cik": (by_source.get("edgar") or {}).get("id") or (wd or {}).get("cik") or None,
            "tickers": (by_source.get("edgar") or {}).get("tickers", []),
            "sic_description": (by_source.get("edgar") or {}).get("sic_description") or None,
            "wikidata_id": (wd or {}).get("id"),
            "inception_year": (wd or {}).get("inception_year") or None,
            "employees": (wd or {}).get("employees") or None,
            "confirmed_by": {c["source"]: c["signals"] for c in confirmed},
        }
        if confirmed:
            return make_evidence(self.name, "company_profile", ctx.domain, Tri.FOUND, **data)
        state = Tri.UNKNOWN if Tri.UNKNOWN in states else Tri.ABSENT
        return make_evidence(self.name, "company_profile", ctx.domain, state, **data)
