"""Enrichment orchestrator - Phase 2e.

Selects supporting providers for an IOC, queries them concurrently, and
returns per-provider results. Does NOT merge or average verdicts.

Design rules:
  - Provider selection uses adapter.supports(ioc_type).
  - If no provider supports the type, return [] (caller decides).
  - Providers are queried concurrently via asyncio.gather.
  - One provider failing must not fail the whole call (fail-soft).
  - Each provider's verdict is preserved separately in the result list.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.integrations.base.adapter import BaseProviderAdapter
from app.integrations.base.errors import classify_error


@dataclass(frozen=True)
class EnrichmentResult:
    indicator: str
    ioc_type: str
    provider: str
    classification: str
    confidence: int
    raw: dict | None = field(default=None)
    error: str | None = field(default=None)
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))


async def enrich(
    indicator: str,
    ioc_type: str,
    adapters: list[BaseProviderAdapter],
) -> list[EnrichmentResult]:
    """Query all supporting adapters concurrently, fail-soft per provider."""
    supporting = [a for a in adapters if a.supports(ioc_type)]
    if not supporting:
        return []

    coros = [_call_one(adapter, indicator, ioc_type) for adapter in supporting]
    return list(await asyncio.gather(*coros))


async def _call_one(
    adapter: BaseProviderAdapter,
    indicator: str,
    ioc_type: str,
) -> EnrichmentResult:
    try:
        resp = await adapter.safe_query(indicator, ioc_type)
    except BaseException as exc:  # noqa: BLE001 - fail-soft boundary
        return EnrichmentResult(
            indicator=indicator,
            ioc_type=ioc_type,
            provider=adapter.name,
            classification="unknown",
            confidence=0,
            raw=None,
            error=classify_error(exc),
            checked_at=datetime.now(UTC),
        )

    return EnrichmentResult(
        indicator=indicator,
        ioc_type=ioc_type,
        provider=adapter.name,
        classification=resp.classification,
        confidence=resp.confidence,
        raw=resp.raw,
        error=resp.error,
        checked_at=resp.checked_at,
    )
