"""VirusTotal v3 adapter - Phase 2c.

Concrete provider adapter that queries VirusTotal for IOC reputation
and maps the response to ProviderResponse.

Design rules:
  - No real network in tests (httpx.MockTransport).
  - 404 from VT means "not in dataset" -> classification='unknown', NOT 'clean'.
  - All-zero stats -> 'unknown', NOT 'clean'.
  - Missing API key -> error='missing_api_key' (caught by safe_query).
  - Path depends on ioc_type; URL uses base64 urlsafe without padding.
  - Confidence heuristics are explicit and documented.
"""
from __future__ import annotations

import base64
from datetime import UTC, datetime

import httpx

from app.integrations.base.adapter import BaseProviderAdapter, ProviderResponse
from app.integrations.base.errors import ProviderError

_BASE_URL = "https://www.virustotal.com/api/v3"

_PATH_BY_TYPE: dict[str, str] = {
    "ipv4": "ip_addresses",
    "domain": "domains",
    "url": "urls",
    "md5": "files",
    "sha1": "files",
    "sha256": "files",
}


class VirusTotalAdapter(BaseProviderAdapter):
    name = "virustotal"
    supported_types = frozenset({"ipv4", "domain", "url", "md5", "sha1", "sha256"})

    def __init__(self, api_key: str, client: httpx.AsyncClient | None = None) -> None:
        self.api_key = (api_key or "").strip()
        self.client = client

    async def query(self, indicator: str, ioc_type: str) -> ProviderResponse:
        if not self.api_key:
            raise ProviderError("missing_api_key")
        if ioc_type not in _PATH_BY_TYPE:
            raise ValueError(f"unsupported ioc_type: {ioc_type!r}")
        if self.client is None:
            raise RuntimeError("httpx client not configured")

        path = self._build_path(indicator, ioc_type)
        url = f"{_BASE_URL}/{path}"

        response = await self.client.get(
            url, headers={"x-apikey": self.api_key}
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

    def _build_path(self, indicator: str, ioc_type: str) -> str:
        base = _PATH_BY_TYPE[ioc_type]
        if ioc_type == "url":
            encoded = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            return f"{base}/{encoded}"
        return f"{base}/{indicator}"

    def _map_payload(
        self, indicator: str, ioc_type: str, payload: dict
    ) -> ProviderResponse:
        stats = (
            payload.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {}) or {}
        )
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)

        if malicious > 0:
            classification = "malicious"
            confidence = min(100, malicious * 10 + suspicious * 3)
        elif suspicious > 0:
            classification = "suspicious"
            confidence = min(100, suspicious * 15)
        elif harmless > 0:
            classification = "clean"
            confidence = 100
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
