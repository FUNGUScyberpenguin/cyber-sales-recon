"""Build a HAR file from pages the engine already fetched, so ZAP can scan them without a request."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

import reconbrief
from reconbrief.http import USER_AGENT, Fetch

TEXT_TYPES = ("text/", "application/json", "application/javascript", "application/xml", "+xml", "+json")


def _is_text(content_type: str) -> bool:
    ctype = content_type.lower()
    return any(t in ctype for t in TEXT_TYPES)


def _entry(fetch: Fetch, started: str) -> dict:
    url = fetch.final_url or fetch.url
    parts = urlsplit(url)
    ctype = fetch.header("content-type") or ""
    encoded = (fetch.header("content-encoding") or "identity").lower() != "identity"
    # A compressed body is not readable text; ZAP still reads the headers and cookies.
    text = "" if encoded or not _is_text(ctype or "text/html") else fetch.body.decode("utf-8", "replace")
    host_header = parts.netloc
    return {
        "startedDateTime": started,
        "time": 1,
        "request": {
            "method": "GET", "url": url, "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Host", "value": host_header}, {"name": "User-Agent", "value": USER_AGENT}],
            "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0,
        },
        "response": {
            "status": fetch.status or 0, "statusText": "", "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in fetch.headers],
            "cookies": [],
            "content": {"size": len(fetch.body), "mimeType": ctype.split(";")[0] or "text/html", "text": text},
            "redirectURL": "", "headersSize": -1, "bodySize": len(fetch.body),
        },
        "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0},
    }


def build_har(fetches: list[Fetch]) -> dict:
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ordered = sorted((f for f in fetches if f.ok), key=lambda f: f.final_url or f.url)
    return {"log": {"version": "1.2", "creator": {"name": "reconbrief", "version": reconbrief.__version__},
                    "entries": [_entry(f, started) for f in ordered]}}


def write_har(fetches: list[Fetch], path) -> int:
    """Write the HAR; return how many pages it holds."""
    har = build_har(fetches)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(har, fh)
    return len(har["log"]["entries"])
