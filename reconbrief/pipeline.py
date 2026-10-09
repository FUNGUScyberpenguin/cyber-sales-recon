"""Runs sources in stages. Each source reports its own health; one failure never stops the run."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from reconbrief.http import AddressGuard, Fetch, HttpClient
from reconbrief.models import Evidence, Health, SourceHealth
from reconbrief.resolver import DnsResolver


@dataclass
class Context:
    domain: str
    dns: DnsResolver
    http: HttpClient
    evidence: list[Evidence] = field(default_factory=list)  # evidence from earlier stages
    company_hint: str = ""  # a company name the user gave; one of the trusted names
    data_dir: Path | None = None  # where downloaded tools (OWASP ZAP) are cached between runs
    captured: list[Fetch] = field(default_factory=list)  # pages the page loader fetched, for passive scanning

    @classmethod
    def create(cls, domain: str, company_hint: str = "", data_dir: Path | None = None) -> "Context":
        resolver = DnsResolver()
        return cls(domain, resolver, HttpClient(AddressGuard(resolver)), company_hint=company_hint,
                   data_dir=data_dir)


@dataclass
class SourceResult:
    health: Health = Health.OK
    evidence: list[Evidence] = field(default_factory=list)
    detail: str = ""


class Source(Protocol):
    name: str
    stage: int

    def run(self, ctx: Context) -> SourceResult: ...


@dataclass
class RunResult:
    evidence: list[Evidence]
    health: list[SourceHealth]

    def failed(self) -> list[SourceHealth]:
        return [h for h in self.health if h.status in (Health.FAILED, Health.PARTIAL)]


def _run_source(source: Source, ctx: Context) -> SourceResult:
    try:
        return source.run(ctx)
    except Exception as exc:  # a broken source is a failed source, not a failed run
        return SourceResult(Health.FAILED, [], f"{type(exc).__name__}: {exc}")


class Pipeline:
    def __init__(self, sources: list[Source], workers: int = 8) -> None:
        self.sources = sources
        self.workers = workers

    def run(self, ctx: Context) -> RunResult:
        health: list[SourceHealth] = []
        for stage in sorted({s.stage for s in self.sources}):
            batch = [s for s in self.sources if s.stage == stage]
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                results = list(pool.map(lambda s: _run_source(s, ctx), batch))
            for source, result in zip(batch, results):
                ctx.evidence.extend(result.evidence)
                health.append(SourceHealth(source.name, result.health, result.detail))
        return RunResult(list(ctx.evidence), health)
