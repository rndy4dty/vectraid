"""Phase 2 integration - end-to-end enrichment pipeline.

Simulates: raw text -> extract IOC -> normalize -> enrich via 3 providers
(VirusTotal, AbuseIPDB, OTX) concurrently. All HTTP is mocked. No network.
"""
from datetime import datetime

import httpx
import pytest

from app.engine.enrichment.orchestrator import enrich
from app.engine.extraction.ioc_extractor import extract_iocs
from app.engine.normalization.ioc_normalizer import normalize
from app.integrations.abuseipdb.adapter import AbuseIPDBAdapter
from app.integrations.otx.adapter import OTXAdapter
from app.integrations.virustotal.adapter import VirusTotalAdapter


def _vt_payload(malicious: int, suspicious: int = 0, harmless: int = 0) -> dict:
    return {
        "data": {
            "id": "x",
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": 10,
                    "timeout": 0,
                }
            },
        }
    }


def _abuse_payload(score: int, reports: int) -> dict:
    return {
        "data": {
            "ipAddress": "203.0.113.10",
            "abuseConfidenceScore": score,
            "totalReports": reports,
        }
    }


def _otx_payload(pulse_count: int) -> dict:
    return {
        "indicator": "203.0.113.10",
        "type": "IPv4",
        "pulse_info": {"count": pulse_count, "pulses": []},
    }


@pytest.mark.asyncio
async def test_end_to_end_enrichment_pipeline():
    # 1. Simulated input text with a mixed blob
    raw_text = (
        "Suspicious C2 activity observed. IP 203.0.113.10 "
        "and domain example.test appear in logs."
    )

    # 2. Extract
    extracted = extract_iocs(raw_text, source="integration:test")
    values_by_type = {(i.value.lower(), i.ioc_type) for i in extracted.iocs}
    assert ("203.0.113.10", "ipv4") in values_by_type
    assert ("example.test", "domain") in values_by_type

    # 3. Normalize (idempotent)
    ip_ioc = next(i for i in extracted.iocs if i.ioc_type == "ipv4")
    normalized_ip = normalize(ip_ioc.value, "ipv4")
    assert normalized_ip == "203.0.113.10"

    # 4. Mock HTTP for all three providers
    vt_calls = {"n": 0}
    abuse_calls = {"n": 0}
    otx_calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "virustotal.com" in url:
            vt_calls["n"] += 1
            return httpx.Response(200, json=_vt_payload(malicious=5, suspicious=1))
        if "abuseipdb.com" in url:
            abuse_calls["n"] += 1
            return httpx.Response(200, json=_abuse_payload(score=90, reports=100))
        if "otx.alienvault.com" in url:
            otx_calls["n"] += 1
            return httpx.Response(200, json=_otx_payload(pulse_count=4))
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:
        vt = VirusTotalAdapter(api_key="vt-key", client=client)
        abuse = AbuseIPDBAdapter(api_key="abuse-key", client=client)
        otx = OTXAdapter(api_key="otx-key", client=client)

        # 5. Enrich IP with all three providers (concurrent, fail-soft)
        results = await enrich(
            indicator="203.0.113.10",
            ioc_type="ipv4",
            adapters=[vt, abuse, otx],
        )

    # 6. Verify per-provider results — no merging, all stored
    assert len(results) == 3
    by_provider = {r.provider: r for r in results}
    assert set(by_provider.keys()) == {"virustotal", "abuseipdb", "otx"}

    assert by_provider["virustotal"].classification == "malicious"
    assert by_provider["abuseipdb"].classification == "malicious"
    assert by_provider["otx"].classification == "malicious"

    # All have a checked_at timestamp
    for r in results:
        assert isinstance(r.checked_at, datetime)
        assert r.checked_at.tzinfo is not None
        assert r.error is None

    # 7. All three providers were actually called
    assert vt_calls["n"] == 1
    assert abuse_calls["n"] == 1
    assert otx_calls["n"] == 1


@pytest.mark.asyncio
async def test_end_to_end_fail_soft_with_one_provider_down():
    """VT times out; AbuseIPDB and OTX still return their verdicts."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "virustotal.com" in url:
            raise httpx.TimeoutException("vt down")
        if "abuseipdb.com" in url:
            return httpx.Response(200, json=_abuse_payload(score=80, reports=50))
        if "otx.alienvault.com" in url:
            return httpx.Response(200, json=_otx_payload(pulse_count=2))
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:
        vt = VirusTotalAdapter(api_key="vt-key", client=client)
        abuse = AbuseIPDBAdapter(api_key="abuse-key", client=client)
        otx = OTXAdapter(api_key="otx-key", client=client)

        results = await enrich(
            indicator="203.0.113.10",
            ioc_type="ipv4",
            adapters=[vt, abuse, otx],
        )

    assert len(results) == 3
    by_provider = {r.provider: r for r in results}
    assert by_provider["virustotal"].classification == "unknown"
    assert by_provider["virustotal"].error == "timeout"
    assert by_provider["abuseipdb"].classification == "malicious"
    assert by_provider["abuseipdb"].error is None
    assert by_provider["otx"].classification == "suspicious"
    assert by_provider["otx"].error is None


@pytest.mark.asyncio
async def test_end_to_end_domain_skips_abuseipdb():
    """Domain enrichment should not call AbuseIPDB (IPv4 only)."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "virustotal.com" in url:
            return httpx.Response(
                200,
                json={"data": {"attributes": {"last_analysis_stats": {
                    "malicious": 0, "suspicious": 0, "harmless": 5,
                    "undetected": 5, "timeout": 0,
                }}}},
            )
        if "abuseipdb.com" in url:
            raise AssertionError("AbuseIPDB should not be called for domain")
        if "otx.alienvault.com" in url:
            return httpx.Response(
                200, json={"pulse_info": {"count": 0, "pulses": []}}
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:
        vt = VirusTotalAdapter(api_key="vt-key", client=client)
        abuse = AbuseIPDBAdapter(api_key="abuse-key", client=client)
        otx = OTXAdapter(api_key="otx-key", client=client)

        results = await enrich(
            indicator="example.test",
            ioc_type="domain",
            adapters=[vt, abuse, otx],
        )

    by_provider = {r.provider: r for r in results}
    assert "abuseipdb" not in by_provider
    assert by_provider["virustotal"].classification == "clean"
    assert by_provider["otx"].classification == "clean"
