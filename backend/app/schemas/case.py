"""Pydantic schemas for Case API - Phase 9b."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


# ---------- requests ----------
class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    priority: str = Field(..., pattern="^(low|medium|high|critical)$")
    created_by: str = Field(..., min_length=1, max_length=200)


class CaseTransitionRequest(BaseModel):
    to: str = Field(..., pattern="^(new|investigating|resolved|closed)$")
    by: str = Field(..., min_length=1, max_length=200)


class CaseAssignRequest(BaseModel):
    assignee: str = Field(..., min_length=1, max_length=200)
    by: str = Field(..., min_length=1, max_length=200)


class CaseNoteRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=4000)
    by: str = Field(..., min_length=1, max_length=200)


class CaseDecisionRequest(BaseModel):
    outcome: str = Field(
        ...,
        pattern="^(false_positive|escalate|duplicate|resolved|close)$",
    )
    rationale: str = Field(..., min_length=1, max_length=4000)
    by: str = Field(..., min_length=1, max_length=200)
    evidence_reference: str | None = None


# ---------- responses ----------
class CaseNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    timestamp: str
    author: str
    text: str


class CaseDecisionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    timestamp: str
    analyst: str
    outcome: str
    rationale: str
    evidence_reference: str | None


class CaseEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    timestamp: str
    actor: str
    action: str
    detail: dict


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    title: str
    status: str
    priority: str
    created_by: str
    assignee: str | None
    evidence_ids: list[str]
    decisions: list[CaseDecisionResponse]
    notes: list[CaseNoteResponse]
    history: list[CaseEventResponse]
