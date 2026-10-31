"""Pydantic schemas for Analysis API - Phase 9e."""
from __future__ import annotations

from pydantic import BaseModel, Field


# ---------- analyze IOC ----------
class AnalyzeIOCRequest(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=500)
    ioc_type: str = Field(
        ...,
        pattern="^(ipv4|domain|url|md5|sha1|sha256|email)$",
    )


class EnrichmentInResponse(BaseModel):
    provider: str
    classification: str
    confidence: int
    error: str | None


class AnalyzeIOCResponse(BaseModel):
    indicator: str
    ioc_type: str
    enrichment: list[EnrichmentInResponse]


# ---------- analyze email ----------
class AnalyzeEmailRequest(BaseModel):
    email_text: str = Field(..., min_length=1)


class AuthInResponse(BaseModel):
    spf: str
    spf_domain: str | None
    dkim: str
    dkim_domain: str | None
    dmarc: str
    dmarc_domain: str | None


class IOCInResponse(BaseModel):
    value: str
    ioc_type: str
    source: str


class FindingInResponse(BaseModel):
    code: str
    severity: str
    detail: str


class ParsedInResponse(BaseModel):
    from_domain: str | None
    reply_to_domain: str | None
    return_path_domain: str | None
    subject: str | None


class AnalyzeEmailResponse(BaseModel):
    parsed: ParsedInResponse
    iocs: list[IOCInResponse]
    auth: AuthInResponse
    findings: list[FindingInResponse]


# ---------- analyze file ----------
class AnalyzeFileRequest(BaseModel):
    content_b64: str = Field(..., min_length=1)
    filename: str = Field(..., min_length=1, max_length=500)


class IdentificationInResponse(BaseModel):
    magic: str
    mime: str
    extension: str
    extension_mismatch: bool
    size: int


class MetadataInResponse(BaseModel):
    md5: str
    sha1: str
    sha256: str
    pe_info: dict | None
    strings_truncated: bool


class YaraMatchInResponse(BaseModel):
    rule_name: str
    tags: list[str]
    meta: dict


class YaraInResponse(BaseModel):
    matches: list[YaraMatchInResponse]
    error: str | None
    timed_out: bool


class ClassificationInResponse(BaseModel):
    classification: str
    confidence: int
    reasons: list[str]


class AnalyzeFileResponse(BaseModel):
    identification: IdentificationInResponse
    metadata: MetadataInResponse
    yara: YaraInResponse
    classification: ClassificationInResponse


# ---------- hunt logs ----------
class HuntLogsRequest(BaseModel):
    logs_text: str = Field(..., min_length=1)
    iocs: list[str] = Field(default_factory=list)


class HuntSummaryInResponse(BaseModel):
    event_count: int
    rule_finding_count: int
    ioc_match_count: int
    unique_hosts: int
    unique_users: int
    severity_breakdown: dict[str, int]
    time_range: list[str | None]


class HuntReportInResponse(BaseModel):
    summary: HuntSummaryInResponse
    skipped: int
    errors: list[str]


class HuntLogsResponse(BaseModel):
    report: HuntReportInResponse
