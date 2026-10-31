"""Pydantic schemas for Evidence API - Phase 9c."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


# ---------- requests ----------
class EvidenceCreateRequest(BaseModel):
    evidence_id: str = Field(..., min_length=1, max_length=200)
    case_id: str = Field(..., min_length=1, max_length=200)
    source_module: str = Field(..., min_length=1, max_length=100)
    evidence_type: str = Field(
        ...,
        pattern="^(email_analysis|file_analysis|hunt_finding|ioc_match|threat_intel)$",
    )
    raw_reference: str = Field(..., min_length=1, max_length=500)
    finding: str = Field(..., min_length=1, max_length=4000)
    timestamp: str = Field(..., min_length=1, max_length=100)
    confidence: int = Field(..., ge=0, le=100)
    provenance: dict = Field(default_factory=dict)


class LinkEvidenceRequest(BaseModel):
    evidence_id: str = Field(..., min_length=1, max_length=200)
    by: str = Field(..., min_length=1, max_length=200)


# ---------- responses ----------
class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: str
    case_id: str
    source_module: str
    evidence_type: str
    raw_reference: str
    finding: str
    timestamp: str
    confidence: int
    provenance: dict
