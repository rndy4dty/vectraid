"""Phase 2c - VirusTotal adapter tests (test-first).

No real network. All HTTP is simulated via httpx.MockTransport.
"""
import base64

import httpx
import pytest

from app.integrations.virustotal.adapter import VirusTotalAdapter


def _make_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _vt_response(stats: dict, indicator_id: str = "abc") -> dict:
    return {
        "data": {
            "id": indicator_id,
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": stats,
            },
        }
    }


# ---------- supported_types ----------
def test_virustotal_supported_types():
    adapter = VirusTotalAdapter(api_key="dummy")
    assert adapter.name == "virustotal"
    for t in ("ipv4", "domain", "url", "md5", "sha1", "sha256"):
        assert adapter.supports(t) is True
    assert adapter.supports("email") is False
    assert adapter.supports("bogus") is False


# ---------- missing api key ----------
@pytest.mark.asyncio
async def test_virustotal_missing_api_key():
    adapter = VirusTotalAdapter(api_key="")

    async def handler(request):
        return httpx.Response(200, json=_vt_response({"malicious": 1}))

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "unknown"
    assert resp.error == "missing_api_key"


# ---------- malicious ----------
@pytest.mark.asyncio
async def test_virustotal_malicious_ipv4():
    adapter = VirusTotalAdapter(api_key="dummy")

    async def handler(request):
        assert "ip_addresses" in str(request.url)
        return httpx.Response(
            200,
            json=_vt_response(
                {"malicious": 5, "suspicious": 2, "harmless": 0,
                 "undetected": 60, "timeout": 0}
            ),
        )

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "malicious"
    assert resp.confidence > 0
    assert resp.error is None
    assert resp.provider == "virustotal"


# ---------- suspicious only ----------
@pytest.mark.asyncio
async def test_virustotal_suspicious_domain():
    adapter = VirusTotalAdapter(api_key="dummy")

    async def handler(request):
        assert "domains" in str(request.url)
        return httpx.Response(
            200,
            json=_vt_response(
                {"malicious": 0, "suspicious": 3, "harmless": 0,
                 "undetected": 50, "timeout": 0}
            ),
        )

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("example.test", "domain")
    assert resp.classification == "suspicious"
    assert resp.confidence > 0


# ---------- clean ----------
@pytest.mark.asyncio
async def test_virustotal_clean_hash():
    adapter = VirusTotalAdapter(api_key="dummy")

    async def handler(request):
        assert "files" in str(request.url)
        return httpx.Response(
            200,
            json=_vt_response(
                {"malicious": 0, "suspicious": 0, "harmless": 5,
                 "undetected": 50, "timeout": 0}
            ),
        )

    async with _make_client(handler) as client:
        adapter.client = client
        h = "a" * 64
        resp = await adapter.safe_query(h, "sha256")
    assert resp.classification == "clean"
    assert resp.confidence == 100


# ---------- all zeros -> unknown, not clean ----------
@pytest.mark.asyncio
async def test_virustotal_all_zero_is_unknown_not_clean():
    adapter = VirusTotalAdapter(api_key="dummy")

    async def handler(request):
        return httpx.Response(
            200,
            json=_vt_response(
                {"malicious": 0, "suspicious": 0, "harmless": 0,
                 "undetected": 0, "timeout": 0}
            ),
        )

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "unknown"
    assert resp.classification != "clean"


# ---------- 404 -> unknown, not clean ----------
@pytest.mark.asyncio
async def test_virustotal_404_is_unknown():
    adapter = VirusTotalAdapter(api_key="dummy")

    async def handler(request):
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.classification == "unknown"
    assert resp.error == "not_found"


# ---------- URL path uses base64 url-safe without padding ----------
@pytest.mark.asyncio
async def test_virustotal_url_path_is_base64():
    adapter = VirusTotalAdapter(api_key="dummy")
    target = "https://example.test/path"
    expected_b64 = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")

    async def handler(request):
        assert expected_b64 in str(request.url)
        return httpx.Response(
            200,
            json=_vt_response(
                {"malicious": 1, "suspicious": 0, "harmless": 0,
                 "undetected": 0, "timeout": 0}
            ),
        )

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query(target, "url")
    assert resp.classification == "malicious"


# ---------- raw is preserved ----------
@pytest.mark.asyncio
async def test_virustotal_raw_is_preserved():
    adapter = VirusTotalAdapter(api_key="dummy")

    payload = _vt_response(
        {"malicious": 1, "suspicious": 0, "harmless": 0,
         "undetected": 0, "timeout": 0}
    )

    async def handler(request):
        return httpx.Response(200, json=payload)

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.raw is not None
    assert resp.raw.get("data", {}).get("attributes", {}).get(
        "last_analysis_stats", {}
    ).get("malicious") == 1


# ---------- checked_at is set ----------
@pytest.mark.asyncio
async def test_virustotal_checked_at_is_utc_aware():
    adapter = VirusTotalAdapter(api_key="dummy")

    async def handler(request):
        return httpx.Response(
            200,
            json=_vt_response(
                {"malicious": 1, "suspicious": 0, "harmless": 0,
                 "undetected": 0, "timeout": 0}
            ),
        )

    async with _make_client(handler) as client:
        adapter.client = client
        resp = await adapter.safe_query("203.0.113.10", "ipv4")
    assert resp.checked_at.tzinfo is not None
    assert resp.checked_at.utcoffset() is not None
