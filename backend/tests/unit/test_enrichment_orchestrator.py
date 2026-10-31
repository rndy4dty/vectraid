"""Phase 2e - Enrichment orchestrator tests (test-first).

Tests orchestration logic with mock adapters. Adapters themselves are
tested in 2c/2d; here we test selection, parallelism, and fail-soft.
"""
from datetime import UTC, datetime

import pytest

from app.engine.enrichment.orchestrator import (
    EnrichmentResult,
    enrich,
)
from app.integrations.base.adapter import BaseProviderAdapter, ProviderResponse


def _make_adapter(name: str, supported: set[str], response_fn):
    """Build a mock adapter that returns a canned response.

    Name and supported_types are set via __init__ so the closure variables
    (name, supported, response_fn) are captured correctly. Query is defined
    in the class body so ABC sees it as concrete.
    """

    class MockAdapter(BaseProviderAdapter):
        supported_types: frozenset[str] = frozenset()

        def __init__(self) -> None:
            self.name = name
            self.supported_types = frozenset(supported)
            self._response_fn = response_fn

        async def query(self, indicator, ioc_type):
            return self._response_fn(self.name, indicator, ioc_type)

    return MockAdapter()


def _ok(name: str, indicator: str, ioc_type: str) -> ProviderResponse:
    return ProviderResponse(
        provider=name,
        indicator=indicator,
        ioc_type=ioc_type,
        classification="malicious",
        confidence=80,
        raw={"mock": name},
        error=None,
        checked_at=datetime.now(UTC),
    )


# ---------- EnrichmentResult shape ----------
def test_enrichment_result_fields():
    r = EnrichmentResult(
        indicator="203.0.113.10",
        ioc_type="ipv4",
        provider="virustotal",
        classification="malicious",
        confidence=80,
        raw={"x": 1},
        error=None,
        checked_at=datetime.now(UTC),
    )
    assert r.indicator == "203.0.113.10"
    assert r.provider == "virustotal"
    assert r.classification == "malicious"


# ---------- selection: only supporting providers are called ----------
@pytest.mark.asyncio
async def test_enrich_calls_only_supporting_providers():
    calls = []

    def resp(name, indicator, ioc_type):
        calls.append(name)
        return _ok(name, indicator, ioc_type)

    vt = _make_adapter("virustotal", {"ipv4", "domain", "url", "md5", "sha1", "sha256"}, resp)
    abuse = _make_adapter("abuseipdb", {"ipv4"}, resp)
    otx = _make_adapter("otx", {"ipv4", "domain", "url", "md5", "sha1", "sha256"}, resp)

    results = await enrich(
        indicator="example.test",
        ioc_type="domain",
        adapters=[vt, abuse, otx],
    )

    assert "virustotal" in calls
    assert "otx" in calls
    assert "abuseipdb" not in calls  # does not support domain
    assert {r.provider for r in results} == {"virustotal", "otx"}


# ---------- no provider for type ----------
@pytest.mark.asyncio
async def test_enrich_no_provider_returns_empty_with_error():
    abuse = _make_adapter("abuseipdb", {"ipv4"}, _ok)

    results = await enrich(
        indicator="example.test",
        ioc_type="domain",
        adapters=[abuse],
    )
    assert results == []


# ---------- fail-soft: one adapter fails, others succeed ----------
@pytest.mark.asyncio
async def test_enrich_does_not_fail_whole_when_one_provider_errors():
    def fail(name, indicator, ioc_type):
        raise RuntimeError("boom")

    def ok(name, indicator, ioc_type):
        return _ok(name, indicator, ioc_type)

    vt = _make_adapter("virustotal", {"ipv4"}, fail)
    abuse = _make_adapter("abuseipdb", {"ipv4"}, ok)

    results = await enrich(
        indicator="203.0.113.10",
        ioc_type="ipv4",
        adapters=[vt, abuse],
    )

    assert len(results) == 2
    by_provider = {r.provider: r for r in results}
    assert by_provider["virustotal"].classification == "unknown"
    assert by_provider["virustotal"].error is not None
    assert by_provider["abuseipdb"].classification == "malicious"
    assert by_provider["abuseipdb"].error is None


# ---------- parallelism (not sequential) ----------
@pytest.mark.asyncio
async def test_enrich_runs_providers_concurrently():
    """Prove concurrency without wall-clock timing.

    Both providers must be *inside* their query() simultaneously.
    We use an asyncio.Barrier that requires both to arrive before either
    can proceed. If the orchestrator ran them sequentially, the first
    would block forever and the test would time out.
    """
    import asyncio

    barrier = asyncio.Barrier(2)

    async def wait_at_barrier(self, indicator, ioc_type):
        await asyncio.wait_for(barrier.wait(), timeout=1.0)
        return _ok(self.name, indicator, ioc_type)

    class A(BaseProviderAdapter):
        name = "a"
        supported_types = frozenset({"ipv4"})
        query = wait_at_barrier

    class B(BaseProviderAdapter):
        name = "b"
        supported_types = frozenset({"ipv4"})
        query = wait_at_barrier

    results = await asyncio.wait_for(
        enrich(
            indicator="203.0.113.10",
            ioc_type="ipv4",
            adapters=[A(), B()],
        ),
        timeout=2.0,
    )
    assert len(results) == 2


# ---------- results are per-provider, not merged ----------
@pytest.mark.asyncio
async def test_enrich_keeps_conflicting_verdicts_separate():
    def ok(name, indicator, ioc_type):
        return _ok(name, indicator, ioc_type)

    def clean(name, indicator, ioc_type):
        return ProviderResponse(
            provider=name,
            indicator=indicator,
            ioc_type=ioc_type,
            classification="clean",
            confidence=100,
            raw=None,
            error=None,
            checked_at=datetime.now(UTC),
        )

    vt = _make_adapter("virustotal", {"ipv4"}, ok)
    abuse = _make_adapter("abuseipdb", {"ipv4"}, clean)

    results = await enrich(
        indicator="203.0.113.10",
        ioc_type="ipv4",
        adapters=[vt, abuse],
    )

    by_provider = {r.provider: r for r in results}
    assert by_provider["virustotal"].classification == "malicious"
    assert by_provider["abuseipdb"].classification == "clean"
    # Both stored; neither overwritten.
