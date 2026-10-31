"""Hunt endpoints - Phase 9e."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.modules.huntscope.parser import parse_events
from app.modules.huntscope.report import build_report
from app.schemas.analysis import (
    HuntLogsRequest,
    HuntLogsResponse,
    HuntReportInResponse,
    HuntSummaryInResponse,
)

router = APIRouter(prefix="/hunt", tags=["hunt"])


@router.post("/logs", response_model=HuntLogsResponse)
def hunt_logs(payload: HuntLogsRequest) -> HuntLogsResponse:
    parsed = parse_events(payload.logs_text)
    if parsed.errors and not parsed.events:
        raise HTTPException(
            status_code=400,
            detail="; ".join(parsed.errors),
        )

    report = build_report(parsed.events, iocs=payload.iocs)

    return HuntLogsResponse(
        report=HuntReportInResponse(
            summary=HuntSummaryInResponse(
                event_count=report.summary.event_count,
                rule_finding_count=report.summary.rule_finding_count,
                ioc_match_count=report.summary.ioc_match_count,
                unique_hosts=report.summary.unique_hosts,
                unique_users=report.summary.unique_users,
                severity_breakdown=report.summary.severity_breakdown,
                time_range=list(report.summary.time_range),
            ),
            skipped=parsed.skipped,
            errors=parsed.errors + report.errors,
        )
    )
