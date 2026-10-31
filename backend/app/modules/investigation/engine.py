"""Investigation Engine - Phase 7f.

Orchestrates the five Investigation components:
  - correlation  (find relationships between evidence)
  - risk         (assess per-case risk)
  - mitre        (map evidence to ATT&CK techniques)
  - timeline     (chronological view of events)

Design rules:
  - Fail-soft: a broken component does not abort the investigation.
  - Deterministic: given the same evidence, produces the same report.
  - All errors are surfaced in summary.errors, never swallowed.
  - Summary counts are always consistent with the underlying lists.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.modules.investigation.correlation import (
    CorrelationResult,
    correlate_evidence,
)
from app.modules.investigation.evidence import Evidence
from app.modules.investigation.mitre import AttackMapping, map_case
from app.modules.investigation.risk import RiskScore, assess_case
from app.modules.investigation.timeline import Timeline, build_timeline


@dataclass(frozen=True)
class InvestigationSummary:
    evidence_count: int
    correlation_count: int
    mitre_technique_count: int
    risk_classification: str
    risk_score: float
    timeline_event_count: int
    modules_involved: list[str] = field(default_factory=list)
    unique_iocs: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class InvestigationReport:
    case_id: str
    evidence: list[Evidence] = field(default_factory=list)
    correlations: list[CorrelationResult] = field(default_factory=list)
    risk: RiskScore | None = None
    mitre_mappings: list[AttackMapping] = field(default_factory=list)
    timeline: Timeline | None = None
    summary: InvestigationSummary | None = None


def run_investigation(
    evidence_list: list[Evidence], case_id: str
) -> InvestigationReport:
    """Run the full Investigation pipeline over the given evidence."""
    errors: list[str] = []

    # 1. Correlation (fail-soft)
    try:
        correlations = correlate_evidence(evidence_list)
    except Exception as exc:  # noqa: BLE001 - fail-soft boundary
        correlations = []
        errors.append(f"correlation failed: {type(exc).__name__}: {exc}")

    # 2. Risk (fail-soft)
    try:
        risk = assess_case(evidence_list)
    except Exception as exc:  # noqa: BLE001
        risk = RiskScore(
            score=0.0,
            classification="insufficient_data",
            breakdown={},
            reasons=[f"risk assessment failed: {exc}"],
        )
        errors.append(f"risk failed: {type(exc).__name__}: {exc}")

    # 3. MITRE (fail-soft)
    try:
        mappings = map_case(evidence_list)
    except Exception as exc:  # noqa: BLE001
        mappings = []
        errors.append(f"mitre failed: {type(exc).__name__}: {exc}")

    # 4. Timeline (fail-soft)
    try:
        timeline = build_timeline(evidence_list, correlations)
    except Exception as exc:  # noqa: BLE001
        timeline = Timeline()
        errors.append(f"timeline failed: {type(exc).__name__}: {exc}")

    # Collect timeline errors too
    if timeline.errors:
        errors.extend(timeline.errors)

    # 5. Build summary
    summary = InvestigationSummary(
        evidence_count=len(evidence_list),
        correlation_count=len(correlations),
        mitre_technique_count=len(mappings),
        risk_classification=risk.classification,
        risk_score=risk.score,
        timeline_event_count=timeline.event_count,
        modules_involved=_modules_involved(evidence_list),
        unique_iocs=_unique_ioc_count(evidence_list),
        errors=errors,
    )

    return InvestigationReport(
        case_id=case_id,
        evidence=list(evidence_list),
        correlations=correlations,
        risk=risk,
        mitre_mappings=mappings,
        timeline=timeline,
        summary=summary,
    )


# ---------- helpers ----------
def _modules_involved(evidence_list: list[Evidence]) -> list[str]:
    return sorted({ev.source_module for ev in evidence_list})


def _unique_ioc_count(evidence_list: list[Evidence]) -> int:
    seen: set[str] = set()
    for ev in evidence_list:
        prov = ev.provenance or {}
        single = prov.get("ioc_value")
        if isinstance(single, str) and single:
            seen.add(single.lower())
        multi = prov.get("ioc_list")
        if isinstance(multi, list):
            for item in multi:
                if isinstance(item, str) and item:
                    seen.add(item.lower())
    return len(seen)
