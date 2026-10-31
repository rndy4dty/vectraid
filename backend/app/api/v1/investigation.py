"""Investigation endpoints - Phase 9d.

Stateless investigation: run the pipeline over a set of evidence IDs and
return the report. Does not modify any case.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.v1.dependencies import get_evidence_store
from app.modules.investigation.engine import run_investigation
from app.modules.investigation.evidence import Evidence, EvidenceStore
from app.schemas.investigation import (
    InvestigateRequest,
    InvestigationReportResponse,
)

router = APIRouter(prefix="/investigate", tags=["investigation"])


@router.post("", response_model=InvestigationReportResponse)
def investigate(
    payload: InvestigateRequest,
    store: EvidenceStore = Depends(get_evidence_store),
) -> object:
    evidence_items: list[Evidence] = []
    for eid in payload.evidence_ids:
        ev = store.get(eid)
        if ev is None:
            raise HTTPException(
                status_code=404, detail=f"evidence not found: {eid}"
            )
        evidence_items.append(ev)

    # Case ID: use the first evidence's case_id if present, else "adhoc"
    case_id = evidence_items[0].case_id if evidence_items else "adhoc"
    return run_investigation(evidence_items, case_id=case_id)
