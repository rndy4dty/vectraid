"""Phase 2b - Error taxonomy and safe_query wrapper tests (test-first)."""

import httpx
import pytest

from app.integrations.base.adapter import BaseProviderAdapter, ProviderResponse
from app.integrations.base.errors import (
    classify_error,
    retry_async,
)


# ---------- classify_error ----------
def test_classify_timeout():
    assert classify_error(httpx.TimeoutException("t/o")) == "timeout"


def test_classify_connect_error():
    assert classify_error(httpx.ConnectError("no route")) == "network_error"


def test_classify_rate_limit():
    req = httpx.Request("GET", "https://x")
    resp = httpx.Response(429, request=req)
    err = httpx.HTTPStatusError("rate", request=req, response=resp)
    assert classify_error(err) == "rate_limited"


def test_classify_provider_error_5xx():
    req = httpx.Request("GET", "https://x")
    resp = httpx.Response(503, request=req)
    err = httpx.HTTPStatusError("down", request=req, response=resp)
    assert classify_error(err) == "provider_error: 503"


def test_classify_client_error_4xx():
    req = httpx.Request("GET", "https://x")
    resp = httpx.Response(400, request=req)
    err = httpx.HTTPStatusError("bad", request=req, response=resp)
    assert classify_error(err) == "client_error: 400"


def test_classify_unknown_exception():
    assert classify_error(RuntimeError("boom")).startswith("unknown")


# ---------- retry_async ----------
@pytest.mark.asyncio
async def test_retry_async_succeeds_first_try():
    calls = {"n": 0}

    async def fn():
        calls["n"] += 1
        return "ok"

    result = await retry_async(fn, max_attempts=3, base_delay=0.0)
    assert result == "ok"
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_retry_async_retries_on_timeout():
    calls = {"n": 0}

    async def fn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.TimeoutException("t/o")
        return "ok"

    result = await retry_async(fn, max_attempts=3, base_delay=0.0)
    assert result == "ok"
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_retry_async_does_not_retry_on_client_error():
    calls = {"n": 0}
    req = httpx.Request("GET", "https://x")

    async def fn():
        calls["n"] += 1
        resp = httpx.Response(400, request=req)
        raise httpx.HTTPStatusError("bad", request=req, response=resp)

    with pytest.raises(httpx.HTTPStatusError):
        await retry_async(fn, max_attempts=3, base_delay=0.0)
    assert calls["n"] == 1  # no retry


@pytest.mark.asyncio
async def test_retry_async_retries_on_5xx():
    calls = {"n": 0}
    req = httpx.Request("GET", "https://x")

    async def fn():
        calls["n"] += 1
        if calls["n"] < 2:
            resp = httpx.Response(503, request=req)
            raise httpx.HTTPStatusError("down", request=req, response=resp)
        return "ok"

    result = await retry_async(fn, max_attempts=3, base_delay=0.0)
    assert result == "ok"
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_retry_async_gives_up_after_max_attempts():
    calls = {"n": 0}

    async def fn():
        calls["n"] += 1
        raise httpx.TimeoutException("t/o")

    with pytest.raises(httpx.TimeoutException):
        await retry_async(fn, max_attempts=3, base_delay=0.0)
    assert calls["n"] == 3


# ---------- safe_query ----------
@pytest.mark.asyncio
async def test_safe_query_returns_unknown_on_timeout():
    class Flaky(BaseProviderAdapter):
        name = "flaky"
        supported_types = frozenset({"ipv4"})

        async def query(self, indicator, ioc_type):
            raise httpx.TimeoutException("t/o")

    adapter = Flaky()
    resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert isinstance(resp, ProviderResponse)
    assert resp.classification == "unknown"
    assert resp.confidence == 0
    assert resp.error == "timeout"
    assert resp.provider == "flaky"


@pytest.mark.asyncio
async def test_safe_query_returns_unknown_on_http_error():
    class Failing(BaseProviderAdapter):
        name = "failing"
        supported_types = frozenset({"ipv4"})

        async def query(self, indicator, ioc_type):
            req = httpx.Request("GET", "https://x")
            resp = httpx.Response(500, request=req)
            raise httpx.HTTPStatusError("down", request=req, response=resp)

    adapter = Failing()
    resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "unknown"
    assert resp.error == "provider_error: 500"


@pytest.mark.asyncio
async def test_safe_query_unsupported_type_does_not_call_query():
    class Strict(BaseProviderAdapter):
        name = "strict"
        supported_types = frozenset({"ipv4"})

        async def query(self, indicator, ioc_type):
            raise AssertionError("query() should not be called")

    adapter = Strict()
    resp = await adapter.safe_query("example.test", "domain")
    assert resp.classification == "unknown"
    assert resp.error == "unsupported_type"
