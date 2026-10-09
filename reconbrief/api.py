"""Client for third-party public data services (crt.sh, RDAP, RIPEstat and so on).

This is not for prospect hosts. Prospect hosts go through the address guard in
http.py. The client refuses any URL on the prospect's own domain, so a source
cannot send a prospect request around the guard by mistake.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from reconbrief.http import USER_AGENT

RETRY_STATUSES = (429, 500, 502, 503, 504)
REDIRECT_CODES = (301, 302, 303, 307, 308)
MAX_REDIRECTS = 3
MAX_BYTES = 50_000_000
MAX_RETRY_WAIT = 30.0

# transport(url, headers, timeout) -> (status, headers, body). Tests replace it.
Transport = Callable[[str, dict, float], tuple]


@dataclass
class ApiResponse:
    url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str | None = None
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None and 200 <= self.status < 300

    def json(self) -> Any:
        """Parsed body, or None when it is not valid JSON."""
        try:
            return json.loads(self.body.decode("utf-8-sig"))
        except (ValueError, UnicodeDecodeError):
            return None

    def why(self) -> str:
        return self.error or f"HTTP {self.status}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # the caller follows redirects itself, checking each hop


_OPENER = urllib.request.build_opener(_NoRedirect)


def _network_transport(url: str, headers: dict, timeout: float):
    request = urllib.request.Request(url, headers=headers)
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read(MAX_BYTES)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read(MAX_BYTES)


class ApiClient:
    def __init__(
        self,
        transport: Transport = _network_transport,
        sleep: Callable[[float], None] = time.sleep,
        timeout: float = 30.0,
        retries: int = 3,
        backoff: float = 2.0,
    ) -> None:
        self.transport = transport
        self.sleep = sleep
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self._forbidden: list[str] = []

    def forbid(self, domain: str) -> None:
        """Refuse every URL on this domain or below it."""
        self._forbidden.append(domain.lower().rstrip("."))

    def _refusal(self, url: str) -> str | None:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" or not host:
            return "bad_url"
        if any(host == d or host.endswith("." + d) for d in self._forbidden):
            return "prospect_host_refused"
        return None

    def get(self, url: str, headers: dict[str, str] | None = None) -> ApiResponse:
        """GET with retries. Redirects are followed by hand, each hop checked like the first URL."""
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            result = self._get_once(current, headers)
            location = result.headers.get("location")
            if result.status not in REDIRECT_CODES or not location:
                result.url = url
                return result
            current = urljoin(current, location)
            refusal = self._refusal(current)
            if refusal:
                return ApiResponse(url, error=refusal)
        return ApiResponse(url, error="too_many_redirects")

    def _get_once(self, url: str, headers: dict[str, str] | None) -> ApiResponse:
        refusal = self._refusal(url)
        if refusal:
            return ApiResponse(url, error=refusal)
        request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
        result = ApiResponse(url)
        for attempt in range(1, self.retries + 2):
            result = ApiResponse(url, attempts=attempt)
            try:
                status, response_headers, body = self.transport(url, request_headers, self.timeout)
            except TimeoutError:
                result.error = "timeout"
            except OSError as exc:
                result.error = f"{type(exc).__name__}"
            else:
                result.status, result.body = status, body
                result.headers = {k.lower(): v for k, v in response_headers.items()}
                if status not in RETRY_STATUSES:
                    return result
            if attempt > self.retries:
                break
            self.sleep(self._wait(result, attempt))
        return result

    def _wait(self, result: ApiResponse, attempt: int) -> float:
        retry_after = result.headers.get("retry-after", "")
        if retry_after.isdigit():
            return min(float(retry_after), MAX_RETRY_WAIT)
        return min(self.backoff * 2 ** (attempt - 1), MAX_RETRY_WAIT)
