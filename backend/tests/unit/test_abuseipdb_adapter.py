"""Phase 2d - AbuseIPDB adapter tests (test-first). No real network."""
import httpx
import pytest

from app.integrations.abuseipdb.adapter import AbuseIPDBAdapter


def _make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _abuse_response(score: int, reports: int = 1) -> dict:
    return {
        "data": {
            "ipAddress": "203.0.113.10",
            "abuseConfidenceScore": score,
            "totalReports": reports,
            "countryCode": "US",
        }
    }


def test_abuse_supported_types_only_ipv4():
    adapter = AbuseIPDBAdapter(api_key="dummy")
    assert adapter.name == "abuseipdb"
    assert adapter.supports("ipv4") is True
    assert adapter.supports("domain") is False
    assert adapter.supports("sha256") is False


@pytest.mark.asyncio
async def test_abuse_missing_api_key():
    adapter = AbuseIPDBAdapter(api_key="")

    async def handler(request):
        return httpx.Response(200, json=_abuse_response(50))

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "unknown"
    assert resp.error == "missing_api_key"


@pytest.mark.asyncio
async def test_abuse_unsupported_type_is_caught_before_query():
    adapter = AbuseIPDBAdapter(api_key="dummy")

    async def handler(request):
        raise AssertionError("HTTP should not be called for unsupported type")

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("example.test", "domain")
    assert resp.classification == "unknown"
    assert resp.error == "unsupported_type"


@pytest.mark.asyncio
async def test_abuse_high_score_is_malicious():
    adapter = AbuseIPDBAdapter(api_key="dummy")

    async def handler(request):
        return httpx.Response(200, json=_abuse_response(90, 100))

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "malicious"
    assert resp.confidence >= 75
    assert resp.error is None


@pytest.mark.asyncio
async def test_abuse_low_score_with_reports_is_suspicious():
    adapter = AbuseIPDBAdapter(api_key="dummy")

    async def handler(request):
        return httpx.Response(200, json=_abuse_response(30, 5))

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "suspicious"


@pytest.mark.asyncio
async def test_abuse_zero_score_zero_reports_is_clean():
    """AbuseIPDB always has data for a valid IP. Score 0 with 0 reports
    means clean, NOT unknown. This differs from VirusTotal."""
    adapter = AbuseIPDBAdapter(api_key="dummy")

    async def handler(request):
        return httpx.Response(200, json=_abuse_response(0, 0))

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "clean"
    assert resp.classification != "unknown"


@pytest.mark.asyncio
async def test_abuse_404_is_unknown():
    adapter = AbuseIPDBAdapter(api_key="dummy")

    async def handler(request):
        return httpx.Response(404, json={"errors": [{"detail": "not found"}]})

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "unknown"
    assert resp.error == "not_found"


@pytest.mark.asyncio
async def test_abuse_header_uses_key():
    adapter = AbuseIPDBAdapter(api_key="secret123")

    async def handler(request):
        assert request.headers.get("Key") == "secret123"
        return httpx.Response(200, json=_abuse_response(10, 1))

    async with _make_client(handler) as client:
        adapter.client = client
        await adapter.safe_query("203.0.113.10", "ipv4")
