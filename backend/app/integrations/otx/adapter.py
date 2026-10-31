"""OTX (AlienVault Open Threat Exchange) adapter - Phase 2d.

Concrete provider adapter for OTX pulses.

Design rules:
  - supported_types = 6 types (IPv4, domain, URL, md5, sha1, sha256).
  - Header uses 'X-OTX-API-KEY'.
  - pulse_info.count >= 3 -> malicious.
  - pulse_info.count >= 1 -> suspicious.
  - pulse_info present and count == 0 -> clean.
  - pulse_info absent -> unknown (cannot conclude clean).
  - 404 -> unknown / not_found.
  - Missing key -> ProviderError('missing_api_key').
"""
from __future__ import annotations

from datetime import UTC, datetime

import httpx

from app.integrations.base.adapter import BaseProviderAdapter, ProviderResponse
from app.integrations.base.errors import ProviderError

_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

_PATH_BY_TYPE: dict[str, str] = {
    "ipv4": "IPv4",
    "domain": "domain",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
}


class OTXAdapter(BaseProviderAdapter):
    name = "otx"
    supported_types = frozenset({"ipv4", "domain", "url", "md5", "sha1", "sha256"})

    def __init__(self, api_key: str, client: httpx.AsyncClient | None = None) -> None:
        self.api_key = (api_key or "").strip()
        self.client = client

    async def query(self, indicator: str, ioc_type: str) -> ProviderResponse:
        if not self.api_key:
            raise ProviderError("missing_api_key")
        if ioc_type not in _PATH_BY_TYPE:
            raise ProviderError("unsupported_type")
        if self.client is None:
            raise ProviderError("client_not_configured")

        path_type = _PATH_BY_TYPE[ioc_type]
        url = f"{_BASE_URL}/{path_type}/{indicator}/general"

        response = await self.client.get(
            url, headers={"X-OTX-API-KEY": self.api_key}
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
        pulse_info = payload.get("pulse_info")

        if pulse_info is None:
            classification: str = "unknown"
            confidence = 0
        else:
            count = int(pulse_info.get("count", 0) or 0)
            if count >= 3:
                classification = "malicious"
                confidence = min(100, count * 20)
            elif count >= 1:
                classification = "suspicious"
                confidence = min(100, count * 30)
            else:
                classification = "clean"
                confidence = 100

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
