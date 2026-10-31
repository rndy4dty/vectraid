"""Phase 3 integration - end-to-end PhishTrace pipeline.

Simulates: .eml -> parse -> extract IOC -> auth analysis -> findings ->
enrich (3 providers, mock HTTP) -> verify per-provider verdicts.

No real network. No real email. All fixtures are synthetic.
"""
from pathlib import Path

import httpx
import pytest

from app.engine.enrichment.orchestrator import enrich
from app.integrations.abuseipdb.adapter import AbuseIPDBAdapter
from app.integrations.otx.adapter import OTXAdapter
from app.integrations.virustotal.adapter import VirusTotalAdapter
from app.modules.phishtrace.auth import analyze_authentication
from app.modules.phishtrace.extractor import extract_from_email
from app.modules.phishtrace.findings import analyze_findings
from app.modules.phishtrace.parser import parse_eml

_FIXTURES = (
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "emails"
)


def _vt_payload(malicious: int) -> dict:
    return {
        "data": {
            "id": "x",
            "type": "domain",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": 0,
                    "harmless": 5 if malicious == 0 else 0,
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
        "indicator": "x",
        "pulse_info": {"count": pulse_count, "pulses": []},
    }


@pytest.mark.asyncio
async def test_full_phishtrace_pipeline():
    # 1. Parse
    parsed = parse_eml((_FIXTURES / "phishing_simulation.eml").read_text())
    assert parsed.headers.from_domain == "spoofed-sender.test"

    # 2. Extract IOC
    ioc_result = extract_from_email(parsed)
    urls = [i for i in ioc_result.iocs if i.ioc_type == "url"]
    domains = [i for i in ioc_result.iocs if i.ioc_type == "domain"]
    assert len(urls) >= 1
    assert len(domains) >= 3

    # 3. Auth analysis
    auth = analyze_authentication(parsed)
    assert auth.details.spf_result == "fail"
    assert auth.details.dkim_result == "fail"
    assert auth.details.dmarc_result == "fail"
    auth_codes = {f.code for f in auth.findings}
    assert "spf_fail" in auth_codes
    assert "dkim_fail" in auth_codes
    assert "dmarc_fail" in auth_codes

    # 4. Findings
    findings = analyze_findings(parsed)
    codes = {f.code for f in findings.findings}
    assert "display_name_brand_mismatch" in codes

    # 5. Enrich the From domain via 3 providers (mock HTTP)
    #    - VirusTotal: malicious
    #    - OTX: 5 pulses -> malicious
    #    - AbuseIPDB: does not support domain, skipped
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "virustotal.com" in url:
            return httpx.Response(200, json=_vt_payload(malicious=7))
        if "abuseipdb.com" in url:
            raise AssertionError("AbuseIPDB should not be called for domain")
        if "otx.alienvault.com" in url:
            return httpx.Response(200, json=_otx_payload(pulse_count=5))
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        vt = VirusTotalAdapter(api_key="vt-key", client=client)
        abuse = AbuseIPDBAdapter(api_key="abuse-key", client=client)
        otx = OTXAdapter(api_key="otx-key", client=client)

        enrich_results = await enrich(
            indicator="spoofed-sender.test",
            ioc_type="domain",
            adapters=[vt, abuse, otx],
        )

    # 6. Verify enrichment per provider — no merging
    by_provider = {r.provider: r for r in enrich_results}
    assert "abuseipdb" not in by_provider  # domain not supported
    assert by_provider["virustotal"].classification == "malicious"
    assert by_provider["otx"].classification == "malicious"
    assert by_provider["virustotal"].error is None
    assert by_provider["otx"].error is None


@pytest.mark.asyncio
async def test_phishtrace_pipeline_survives_provider_failure():
    """If VirusTotal times out, OTX still returns verdict; pipeline completes."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "virustotal.com" in url:
            raise httpx.TimeoutException("vt down")
        if "otx.alienvault.com" in url:
            return httpx.Response(200, json=_otx_payload(pulse_count=3))
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        vt = VirusTotalAdapter(api_key="vt-key", client=client)
        otx = OTXAdapter(api_key="otx-key", client=client)

        results = await enrich(
            indicator="spoofed-sender.test",
            ioc_type="domain",
            adapters=[vt, otx],
        )

    by_provider = {r.provider: r for r in results}
    assert by_provider["virustotal"].classification == "unknown"
    assert by_provider["virustotal"].error == "timeout"
    assert by_provider["otx"].classification == "malicious"


def test_pipeline_all_findings_are_structured():
    """Every finding across all analysis layers has code/severity/detail."""
    parsed = parse_eml((_FIXTURES / "phishing_simulation.eml").read_text())

    auth = analyze_authentication(parsed)
    for f in auth.findings:
        assert f.code
        assert f.severity in {"info", "low", "medium", "high"}
        assert f.detail

    findings = analyze_findings(parsed)
    for f in findings.findings:
        assert f.code
        assert f.severity in {"info", "low", "medium", "high"}
        assert f.detail
