"""Phase 2a - Base provider adapter contract tests (test-first).

Locks the shape of BaseProviderAdapter and ProviderResponse before any
concrete provider is implemented.
"""
from datetime import UTC, datetime

import pytest

from app.integrations.base.adapter import (
    BaseProviderAdapter,
    ProviderResponse,
)


# ---------- ProviderResponse shape ----------
def test_provider_response_fields():
    r = ProviderResponse(
        provider="example",
        indicator="203.0.113.10",
        ioc_type="ipv4",
        classification="malicious",
        confidence=80,
        raw={"score": 80},
        error=None,
        checked_at=datetime.now(UTC),
    )
    assert r.provider == "example"
    assert r.indicator == "203.0.113.10"
    assert r.ioc_type == "ipv4"
    assert r.classification == "malicious"
    assert r.confidence == 80
    assert r.raw == {"score": 80}
    assert r.error is None
    assert isinstance(r.checked_at, datetime)


def test_provider_response_rejects_bad_classification():
    with pytest.raises(ValueError):
        ProviderResponse(
            provider="x", indicator="x", ioc_type="ipv4",
            classification="bogus", confidence=10,
            raw=None, error=None,
            checked_at=datetime.now(UTC),
        )


def test_provider_response_rejects_confidence_out_of_range():
    with pytest.raises(ValueError):
        ProviderResponse(
            provider="x", indicator="x", ioc_type="ipv4",
            classification="malicious", confidence=101,
            raw=None, error=None,
            checked_at=datetime.now(UTC),
        )
    with pytest.raises(ValueError):
        ProviderResponse(
            provider="x", indicator="x", ioc_type="ipv4",
            classification="malicious", confidence=-1,
            raw=None, error=None,
            checked_at=datetime.now(UTC),
        )


def test_provider_response_unknown_is_not_clean():
    """Critical semantic: 'unknown' must be distinct from 'clean'."""
    unknown = ProviderResponse(
        provider="x", indicator="x", ioc_type="ipv4",
        classification="unknown", confidence=0,
        raw=None, error=None,
        checked_at=datetime.now(UTC),
    )
    clean = ProviderResponse(
        provider="x", indicator="x", ioc_type="ipv4",
        classification="clean", confidence=100,
        raw=None, error=None,
        checked_at=datetime.now(UTC),
    )
    assert unknown.classification != clean.classification


# ---------- BaseProviderAdapter contract ----------
def test_base_adapter_is_abstract():
    with pytest.raises(TypeError):
        BaseProviderAdapter()  # cannot instantiate ABC


def test_concrete_adapter_must_implement_query():
    class Incomplete(BaseProviderAdapter):
        name = "incomplete"
        supported_types = frozenset({"ipv4"})
        # no query() -> abstract

    with pytest.raises(TypeError):
        Incomplete()


def test_concrete_adapter_works():
    class Fake(BaseProviderAdapter):
        name = "fake"
        supported_types = frozenset({"ipv4", "domain"})

        async def query(self, indicator, ioc_type):
            return ProviderResponse(
                provider=self.name,
                indicator=indicator,
                ioc_type=ioc_type,
                classification="unknown",
                confidence=0,
                raw=None,
                error=None,
                checked_at=datetime.now(UTC),
            )

    adapter = Fake()
    assert adapter.name == "fake"
    assert adapter.supports("ipv4") is True
    assert adapter.supports("domain") is True
    assert adapter.supports("sha256") is False
    assert adapter.supports("md5") is False
    assert adapter.supports("bogus") is False


@pytest.mark.asyncio
async def test_concrete_adapter_query_returns_provider_response():
    class Fake(BaseProviderAdapter):
        name = "fake"
        supported_types = frozenset({"ipv4"})

        async def query(self, indicator, ioc_type):
            return ProviderResponse(
                provider=self.name,
                indicator=indicator,
                ioc_type=ioc_type,
                classification="malicious",
                confidence=75,
                raw={"data": "x"},
                error=None,
                checked_at=datetime.now(UTC),
            )

    adapter = Fake()
    resp = await adapter.query("203.0.113.10", "ipv4")
    assert isinstance(resp, ProviderResponse)
    assert resp.provider == "fake"
    assert resp.indicator == "203.0.113.10"
    assert resp.classification == "malicious"
