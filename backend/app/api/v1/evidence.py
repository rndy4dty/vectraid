"""Evidence endpoints - Phase 9c.

Add, get, and list evidence. Linking/unlinking evidence to cases is in
cases.py (POST /cases/{id}/evidence) since it modifies the case.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.v1.dependencies import get_evidence_store
from app.modules.investigation.evidence import (
    Evidence,
    EvidenceStore,
    EvidenceType,
)
from app.schemas.evidence import (
    EvidenceCreateRequest,
    EvidenceResponse,
)

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.post("", status_code=201, response_model=EvidenceResponse)
def create_evidence(
    payload: EvidenceCreateRequest,
    store: EvidenceStore = Depends(get_evidence_store),
) -> Evidence:
    try:
        evidence = Evidence(
            evidence_id=payload.evidence_id,
            case_id=payload.case_id,
            source_module=payload.source_module,
            evidence_type=EvidenceType(payload.evidence_type),
            raw_reference=payload.raw_reference,
            finding=payload.finding,
            timestamp=payload.timestamp,
            confidence=payload.confidence,
            provenance=payload.provenance,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        store.add(evidence)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return evidence


@router.get("/{evidence_id}", response_model=EvidenceResponse)
def get_evidence(
    evidence_id: str,
    store: EvidenceStore = Depends(get_evidence_store),
) -> Evidence:
    evidence = store.get(evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    return evidence


@router.get("", response_model=list[EvidenceResponse])
def list_evidence(
    case_id: str | None = Query(default=None),
    store: EvidenceStore = Depends(get_evidence_store),
) -> list[Evidence]:
    if case_id is not None:
        return store.list_by_case(case_id)
    return store.list_all()
