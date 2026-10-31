"""AbuseIPDB adapter - Phase 2d.

Concrete provider adapter for IPv4 reputation via AbuseIPDB v2.

Design rules:
  - supported_types = {"ipv4"} only (AbuseIPDB is IP-only).
  - Header uses 'Key' (not Authorization, not x-apikey).
  - Score >= 75 with reports -> malicious.
  - Score >= 25 with reports -> suspicious.
  - Score > 0 with reports  -> suspicious.
  - Score == 0 AND reports == 0 -> clean (AbuseIPDB always has data for
    a valid IP, so zero here genuinely means no abuse reports).
  - 404 -> unknown / not_found.
  - Missing key -> ProviderError('missing_api_key').
"""
from __future__ import annotations

from datetime import UTC, datetime

import httpx

from app.integrations.base.adapter import BaseProviderAdapter, ProviderResponse
from app.integrations.base.errors import ProviderError

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBAdapter(BaseProviderAdapter):
    name = "abuseipdb"
    supported_types = frozenset({"ipv4"})

    def __init__(self, api_key: str, client: httpx.AsyncClient | None = None) -> None:
        self.api_key = (api_key or "").strip()
        self.client = client

    async def query(self, indicator: str, ioc_type: str) -> ProviderResponse:
        if not self.api_key:
            raise ProviderError("missing_api_key")
        if ioc_type != "ipv4":
            raise ProviderError("unsupported_type")
        if self.client is None:
            raise ProviderError("client_not_configured")

        response = await self.client.get(
            _BASE_URL,
            params={"ipAddress": indicator, "maxAgeInDays": "90"},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )

        if response.status_code == 404:
            return ProviderResponse(
                provider=self.name,
                indicator=indicator,
                ioc_type=ioc_type,
                classification="unknown",
                confidence=0,
                raw=None,
                error="not_found",
                checked_at=datetime.now(UTC),
            )

        response.raise_for_status()
        payload = response.json()
        return self._map_payload(indicator, ioc_type, payload)

    def _map_payload(
        self, indicator: str, ioc_type: str, payload: dict
    ) -> ProviderResponse:
        data = payload.get("data", {}) or {}
        score = int(data.get("abuseConfidenceScore", 0) or 0)
        reports = int(data.get("totalReports", 0) or 0)

        if reports == 0 and score == 0:
            classification: str = "clean"
            confidence = 100
        elif score >= 75:
            classification = "malicious"
            confidence = min(100, score)
        elif score >= 25:
            classification = "suspicious"
            confidence = score
        elif score > 0:
            classification = "suspicious"
            confidence = score
        else:
            classification = "unknown"
            confidence = 0

        return ProviderResponse(
            provider=self.name,
            indicator=indicator,
            ioc_type=ioc_type,
            classification=classification,  # type: ignore[arg-type]
            confidence=confidence,
            raw=payload,
            error=None,
            checked_at=datetime.now(UTC),
        )
