"""Combined report schemas - Phase 9d.

This module composes CaseResponse and InvestigationReportResponse into
a single CaseReportResponse. It is kept separate from both case.py and
investigation.py to avoid circular imports.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from app.schemas.case import CaseResponse
from app.schemas.investigation import InvestigationReportResponse


class CaseReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case: CaseResponse
    investigation: InvestigationReportResponse
