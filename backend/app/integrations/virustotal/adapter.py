"""virustotal adapter — Phase 2."""
from app.integrations.base.adapter import BaseProviderAdapter, ProviderResponse


class Adapter(BaseProviderAdapter):
    name = "virustotal"

    async def query(self, indicator: str, ioc_type: str) -> ProviderResponse:
        raise NotImplementedError("Phase 2 — to be implemented")
