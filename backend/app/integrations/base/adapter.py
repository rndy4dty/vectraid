"""Base adapter contract for all TI providers."""
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ProviderResponse:
    provider: str
    indicator: str
    ioc_type: str
    classification: str
    confidence: int
    raw: dict | None = None
    error: str | None = None


class BaseProviderAdapter(ABC):
    name: str = "base"

    @abstractmethod
    async def query(self, indicator: str, ioc_type: str) -> ProviderResponse:
        ...
