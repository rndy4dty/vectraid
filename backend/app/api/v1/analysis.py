"""Analysis endpoints - Phase 9e.

Stateless analysis: IOC enrichment, email forensics, file static analysis.
All endpoints return evidence-shaped data; persisting evidence is the
caller's responsibility (via POST /evidence).
"""
from __future__ import annotations

import base64
import tempfile
from pathlib import Path

import httpx
from fastapi import APIRouter, HTTPException

from app.core.config import get_settings
from app.engine.enrichment.orchestrator import enrich
from app.integrations.abuseipdb.adapter import AbuseIPDBAdapter
from app.integrations.otx.adapter import OTXAdapter
from app.integrations.virustotal.adapter import VirusTotalAdapter
from app.modules.maltrace.classifier import classify_file
from app.modules.maltrace.identifier import identify_file
from app.modules.maltrace.metadata import extract_metadata
from app.modules.maltrace.yara_scanner import compile_rules, scan_file
from app.modules.phishtrace.auth import analyze_authentication
from app.modules.phishtrace.extractor import extract_from_email
from app.modules.phishtrace.findings import analyze_findings
from app.modules.phishtrace.parser import parse_eml
from app.schemas.analysis import (
    AnalyzeEmailRequest,
    AnalyzeEmailResponse,
    AnalyzeFileRequest,
    AnalyzeFileResponse,
    AnalyzeIOCRequest,
    AnalyzeIOCResponse,
    AuthInResponse,
    ClassificationInResponse,
    EnrichmentInResponse,
    FindingInResponse,
    HuntLogsResponse,
    IdentificationInResponse,
    IOCInResponse,
    MetadataInResponse,
    ParsedInResponse,
    YaraInResponse,
    YaraMatchInResponse,
)

router = APIRouter(prefix="/analyze", tags=["analysis"])


# ---------- analyze IOC ----------
@router.post("/ioc", response_model=AnalyzeIOCResponse)
async def analyze_ioc(payload: AnalyzeIOCRequest) -> AnalyzeIOCResponse:
    # In Phase 9, adapters are created without API keys; enrichment returns
    # unknown for each provider. Phase 11 injects real keys.
    settings = get_settings()
    async with httpx.AsyncClient(
        timeout=settings.ti_request_timeout,
    ) as client:
        adapters = [
            VirusTotalAdapter(
                api_key=settings.virustotal_api_key, client=client
            ),
            AbuseIPDBAdapter(
                api_key=settings.abuseipdb_api_key, client=client
            ),
            OTXAdapter(api_key=settings.otx_api_key, client=client),
        ]
        results = await enrich(
            indicator=payload.indicator,
            ioc_type=payload.ioc_type,
            adapters=adapters,
        )
    enrichment = [
        EnrichmentInResponse(
            provider=r.provider,
            classification=r.classification,
            confidence=r.confidence,
            error=r.error,
        )
        for r in results
    ]
    return AnalyzeIOCResponse(
        indicator=payload.indicator,
        ioc_type=payload.ioc_type,
        enrichment=enrichment,
    )


# ---------- analyze email ----------
@router.post("/email", response_model=AnalyzeEmailResponse)
def analyze_email(payload: AnalyzeEmailRequest) -> AnalyzeEmailResponse:
    # Sanity: must look like an email (has at least one header line)
    import re as _re

    _header_re = _re.compile(
        r"^(From|Subject|Received|Date|To|Return-Path):",
        _re.MULTILINE,
    )
    if not _header_re.search(payload.email_text):
        raise HTTPException(
            status_code=400,
            detail="input does not look like an email (no recognized headers)",
        )
    try:
        parsed = parse_eml(payload.email_text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    ioc_result = extract_from_email(parsed)
    auth_result = analyze_authentication(parsed)
    findings_result = analyze_findings(parsed)

    return AnalyzeEmailResponse(
        parsed=ParsedInResponse(
            from_domain=parsed.headers.from_domain,
            reply_to_domain=parsed.headers.reply_to_domain,
            return_path_domain=parsed.headers.return_path_domain,
            subject=parsed.headers.subject,
        ),
        iocs=[
            IOCInResponse(value=i.value, ioc_type=i.ioc_type, source=i.source)
            for i in ioc_result.iocs
        ],
        auth=AuthInResponse(
            spf=auth_result.details.spf_result,
            spf_domain=auth_result.details.spf_domain,
            dkim=auth_result.details.dkim_result,
            dkim_domain=auth_result.details.dkim_domain,
            dmarc=auth_result.details.dmarc_result,
            dmarc_domain=auth_result.details.dmarc_domain,
        ),
        findings=[
            FindingInResponse(
                code=f.code, severity=f.severity, detail=f.detail
            )
            for f in findings_result.findings
        ],
    )


# ---------- analyze file ----------
@router.post("/file", response_model=AnalyzeFileResponse)
def analyze_file(payload: AnalyzeFileRequest) -> AnalyzeFileResponse:
    try:
        raw = base64.b64decode(payload.content_b64, validate=True)
    except Exception as exc:  # noqa: BLE001 - base64 errors
        raise HTTPException(
            status_code=422, detail="invalid base64 content"
        ) from exc

    with tempfile.NamedTemporaryFile(
        suffix=Path(payload.filename).suffix, delete=False
    ) as tmp:
        tmp.write(raw)
        tmp_path = tmp.name

    try:
        ident = identify_file(tmp_path)
        metadata = extract_metadata(tmp_path)
        rules = compile_rules()
        yara_result = scan_file(tmp_path, rules)
        classification = classify_file(ident, metadata, yara_result)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return AnalyzeFileResponse(
        identification=IdentificationInResponse(
            magic=ident.magic,
            mime=ident.mime,
            extension=ident.extension,
            extension_mismatch=ident.extension_mismatch,
            size=ident.size,
        ),
        metadata=MetadataInResponse(
            md5=metadata.md5,
            sha1=metadata.sha1,
            sha256=metadata.sha256,
            pe_info=(
                {
                    "machine": metadata.pe_info.machine,
                    "subsystem": metadata.pe_info.subsystem,
                    "entry_point": metadata.pe_info.entry_point,
                    "section_count": metadata.pe_info.section_count,
                }
                if metadata.pe_info
                else None
            ),
            strings_truncated=metadata.strings_truncated,
        ),
        yara=YaraInResponse(
            matches=[
                YaraMatchInResponse(
                    rule_name=m.rule_name, tags=m.tags, meta=m.meta
                )
                for m in yara_result.matches
            ],
            error=yara_result.error,
            timed_out=yara_result.timed_out,
        ),
        classification=ClassificationInResponse(
            classification=classification.classification,
            confidence=classification.confidence,
            reasons=classification.reasons,
        ),
    )


# ---------- hunt logs ----------
@router.post("/../hunt/logs", response_model=HuntLogsResponse, include_in_schema=False)
def _placeholder_hunt() -> HuntLogsResponse:
    raise HTTPException(status_code=404)
