"""HuntScope report aggregation - Phase 5e.

Combines rule findings (Phase 5c) and IOC matches (Phase 5d) into a
single HuntReport with an aggregated summary. This is the entry point
for callers who want one object to hand to Case Management.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.modules.huntscope.ioc_matcher import IOCMatch, match_iocs
from app.modules.huntscope.parser import NormalizedEvent
from app.modules.huntscope.rules import BaseRule, Finding, hunt


@dataclass(frozen=True)
class HuntSummary:
    event_count: int
    rule_finding_count: int
    ioc_match_count: int
    unique_hosts: int
    unique_users: int
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    time_range: tuple[str | None, str | None] = (None, None)


@dataclass(frozen=True)
class HuntReport:
    rule_findings: list[Finding] = field(default_factory=list)
    ioc_matches: list[IOCMatch] = field(default_factory=list)
    summary: HuntSummary = field(
        default_factory=lambda: HuntSummary(
            event_count=0,
            rule_finding_count=0,
            ioc_match_count=0,
            unique_hosts=0,
            unique_users=0,
        )
    )
    errors: list[str] = field(default_factory=list)


def build_report(
    events: list[NormalizedEvent],
    rules: list[BaseRule] | None = None,
    iocs: list[str] | None = None,
    ioc_types: dict[str, str] | None = None,
) -> HuntReport:
    """Run rules and IOC matching, aggregate into a single report."""
    rule_result = hunt(events, rules=rules)

    ioc_result = match_iocs(events, iocs or [], ioc_types=ioc_types)

    errors: list[str] = list(rule_result.errors) + list(ioc_result.errors)

    summary = HuntSummary(
        event_count=len(events),
        rule_finding_count=len(rule_result.findings),
        ioc_match_count=len(ioc_result.matches),
        unique_hosts=_unique_count(events, "hostname"),
        unique_users=_unique_count(events, "user"),
        severity_breakdown=_severity_breakdown(rule_result.findings),
        time_range=_time_range(events),
    )

    return HuntReport(
        rule_findings=rule_result.findings,
        ioc_matches=ioc_result.matches,
        summary=summary,
        errors=errors,
    )


# ---------- helpers ----------
def _unique_count(events: list[NormalizedEvent], field_name: str) -> int:
    values = {getattr(e, field_name) for e in events}
    values.discard(None)
    return len(values)


def _severity_breakdown(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def _time_range(
    events: list[NormalizedEvent],
) -> tuple[str | None, str | None]:
    stamps = [e.timestamp for e in events if e.timestamp]
    if not stamps:
        return (None, None)
    # ISO-8601 strings sort lexicographically.
    return (min(stamps), max(stamps))
