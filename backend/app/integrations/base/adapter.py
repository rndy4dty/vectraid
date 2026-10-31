"""Base adapter contract for all Threat Intelligence providers - Phase 2a.

Two pieces:
  - ProviderResponse: immutable snapshot of one provider's verdict on one IOC.
  - BaseProviderAdapter: abstract contract every concrete provider implements.

Design rules (locked by tests):
  - classification is one of: malicious | suspicious | clean | unknown
  - 'unknown' is NOT 'clean' (critical semantic)
  - confidence is 0..100
  - checked_at is always a timezone-aware UTC datetime
  - supports() derives from supported_types, not per-adapter override
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from app.integrations.base.errors import classify_error, retry_async

Classification = Literal["malicious", "suspicious", "clean", "unknown"]
_ALLOWED: frozenset[str] = frozenset(
    {"malicious", "suspicious", "clean", "unknown"}
)


@dataclass(frozen=True)
class ProviderResponse:
    provider: str
    indicator: str
    ioc_type: str
    classification: Classification
    confidence: int
    raw: dict | None = field(default=None)
    error: str | None = field(default=None)
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.classification not in _ALLOWED:
            raise ValueError(
                f"classification must be one of {sorted(_ALLOWED)}, "
                f"got {self.classification!r}"
            )
        if not isinstance(self.confidence, int) or isinstance(self.confidence, bool):
            raise ValueError(
                f"confidence must be int, got {type(self.confidence).__name__}"
            )
        if not (0 <= self.confidence <= 100):
            raise ValueError(
                f"confidence must be 0..100, got {self.confidence}"
            )
        if self.checked_at.tzinfo is None:
            raise ValueError("checked_at must be timezone-aware (UTC)")


class BaseProviderAdapter(ABC):
    """Every TI provider adapter inherits from this.

    Subclasses must declare:
      - name: str
      - supported_types: frozenset[str]
      - async def query(indicator, ioc_type) -> ProviderResponse
    """

    name: str = "base"
    supported_types: frozenset[str] = frozenset()

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.supported_types

    @abstractmethod
    async def query(self, indicator: str, ioc_type: str) -> ProviderResponse:
        """Query the provider for this indicator. Must not raise on API errors;
        return ProviderResponse with error field populated instead.
        """
        ...

    async def safe_query(self, indicator: str, ioc_type: str) -> ProviderResponse:
        """Fail-soft wrapper around query(): timeout + retry + error mapping.

        Never raises. Returns ProviderResponse with classification='unknown'
        and error populated on any failure. Checks supports() first.
        """
        if not self.supports(ioc_type):
            return ProviderResponse(
                provider=self.name,
                indicator=indicator,
                ioc_type=ioc_type,
                classification="unknown",
                confidence=0,
                raw=None,
                error="unsupported_type",
            )

        try:
            return await retry_async(
                lambda: self.query(indicator, ioc_type),
                max_attempts=3,
                base_delay=0.0,
            )
        except BaseException as exc:  # noqa: BLE001 - fail-soft boundary
            return ProviderResponse(
                provider=self.name,
                indicator=indicator,
                ioc_type=ioc_type,
                classification="unknown",
                confidence=0,
                raw=None,
                error=classify_error(exc),
            )
