"""Enrichment orchestrator — Phase 2."""
from dataclasses import dataclass


@dataclass
class EnrichmentResult:
    indicator: str
    ioc_type: str
    provider: str
    classification: str
    confidence: int
    raw_response: dict | None = None


def enrich(indicator: str, ioc_type: str) -> list[EnrichmentResult]:
    raise NotImplementedError("Phase 2 — to be implemented")
