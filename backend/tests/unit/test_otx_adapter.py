"""Phase 2d - OTX adapter tests (test-first). No real network."""
import httpx
import pytest

from app.integrations.otx.adapter import OTXAdapter


def _make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _otx_response(pulse_count: int, indicator_type: str = "IPv4") -> dict:
    return {
        "indicator": "203.0.113.10",
        "type": indicator_type,
        "pulse_info": {
            "count": pulse_count,
            "pulses": [],
        },
    }


def test_otx_supported_types():
    adapter = OTXAdapter(api_key="dummy")
    assert adapter.name == "otx"
    for t in ("ipv4", "domain", "url", "md5", "sha1", "sha256"):
        assert adapter.supports(t) is True
    assert adapter.supports("email") is False


@pytest.mark.asyncio
async def test_otx_missing_api_key():
    adapter = OTXAdapter(api_key="")

    async def handler(request):
        return httpx.Response(200, json=_otx_response(1))

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "unknown"
    assert resp.error == "missing_api_key"


@pytest.mark.asyncio
async def test_otx_many_pulses_is_malicious():
    adapter = OTXAdapter(api_key="dummy")

    async def handler(request):
        return httpx.Response(200, json=_otx_response(5))

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "malicious"
    assert resp.confidence > 0


@pytest.mark.asyncio
async def test_otx_few_pulses_is_suspicious():
    adapter = OTXAdapter(api_key="dummy")

    async def handler(request):
        return httpx.Response(200, json=_otx_response(1))

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "suspicious"


@pytest.mark.asyncio
async def test_otx_zero_pulses_with_pulse_info_is_clean():
    adapter = OTXAdapter(api_key="dummy")

    async def handler(request):
        return httpx.Response(200, json=_otx_response(0))

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "clean"


@pytest.mark.asyncio
async def test_otx_missing_pulse_info_is_unknown():
    """If pulse_info is absent entirely, we cannot conclude clean."""
    adapter = OTXAdapter(api_key="dummy")

    async def handler(request):
        return httpx.Response(200, json={"indicator": "203.0.113.10"})

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "unknown"
    assert resp.classification != "clean"


@pytest.mark.asyncio
async def test_otx_404_is_unknown():
    adapter = OTXAdapter(api_key="dummy")

    async def handler(request):
        return httpx.Response(404, json={"detail": "not found"})

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "unknown"
    assert resp.error == "not_found"


@pytest.mark.asyncio
async def test_otx_header_uses_x_otx_api_key():
    adapter = OTXAdapter(api_key="secret-otx")

    async def handler(request):
        assert request.headers.get("X-OTX-API-KEY") == "secret-otx"
        return httpx.Response(200, json=_otx_response(1))

    async with _make_client(handler) as client:
        adapter.client = client
        await adapter.safe_query("203.0.113.10", "ipv4")
