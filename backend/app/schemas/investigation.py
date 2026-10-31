"""Pydantic schemas for Investigation API - Phase 9d."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class InvestigateRequest(BaseModel):
    evidence_ids: list[str] = Field(default_factory=list)


# ---------- sub-responses ----------
class EvidenceInReport(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: str
    case_id: str
    source_module: str
    evidence_type: str
    raw_reference: str
    finding: str
    timestamp: str
    confidence: int


class CorrelationInReport(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    correlation_id: str
    evidence_a: str
    evidence_b: str
    correlation_type: str
    strength: int
    detail: str
    shared_indicators: list[str]


class RiskInReport(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    score: float
    classification: str
    breakdown: dict[str, float]
    reasons: list[str]


class MitreMappingInReport(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    technique_id: str
    technique_name: str
    tactic: str
    confidence: int
    evidence_reference: str
    rationale: str


class TimelineEventInReport(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    timestamp: str
    description: str
    source_module: str
    evidence_reference: str
    severity: str
    event_type: str
    related_iocs: list[str]


class TimelineInReport(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    events: list[TimelineEventInReport]
    start_time: str | None
    end_time: str | None
    event_count: int
    errors: list[str]


class InvestigationSummaryInReport(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_count: int
    correlation_count: int
    mitre_technique_count: int
    risk_classification: str
    risk_score: float
    timeline_event_count: int
    modules_involved: list[str]
    unique_iocs: int
    errors: list[str]


# ---------- full report ----------
class InvestigationReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    evidence: list[EvidenceInReport]
    correlations: list[CorrelationInReport]
    risk: RiskInReport | None
    mitre_mappings: list[MitreMappingInReport]
    timeline: TimelineInReport | None
    summary: InvestigationSummaryInReport
