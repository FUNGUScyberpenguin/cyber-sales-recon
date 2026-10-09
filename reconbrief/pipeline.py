"""Runs sources in stages. Each source reports its own health; one failure never stops the run."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Protocol

from reconbrief.api import ApiClient
from reconbrief.http import AddressGuard, HttpClient
from reconbrief.models import Evidence, Health, SourceHealth
from reconbrief.resolver import DnsResolver


@dataclass
class Context:
    domain: str
    dns: DnsResolver
    http: HttpClient
    evidence: list[Evidence] = field(default_factory=list)  # evidence from earlier stages
    api: ApiClient = field(default_factory=ApiClient)  # third-party public services only

    def __post_init__(self) -> None:
        self.api.forbid(self.domain)

    @classmethod
    def create(cls, domain: str) -> "Context":
        resolver = DnsResolver()
        return cls(domain, resolver, HttpClient(AddressGuard(resolver)))


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
