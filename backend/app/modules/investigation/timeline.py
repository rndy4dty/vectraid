"""Investigation timeline builder - Phase 7e.

Combines evidence and correlations into a single chronological timeline
of what happened, ordered by original event time (not analysis time).

Design rules:
  - Timestamps are parsed once; unparseable entries go to errors.
  - Timeline is ordered by event time ascending.
  - Severity derives from evidence confidence: <40 low, 40-69 medium, >=70 high.
  - event_type derives from evidence_type; correlations are their own type.
  - Correlations get the earlier of their two evidence timestamps.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from app.modules.investigation.correlation import CorrelationResult
from app.modules.investigation.evidence import Evidence, EvidenceType


@dataclass(frozen=True)
class TimelineEvent:
    event_id: str
    timestamp: str
    description: str
    source_module: str
    evidence_reference: str
    severity: str
    event_type: str
    related_iocs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Timeline:
    events: list[TimelineEvent] = field(default_factory=list)
    start_time: str | None = None
    end_time: str | None = None
    event_count: int = 0
    errors: list[str] = field(default_factory=list)


_EVENT_TYPE_BY_EVIDENCE = {
    EvidenceType.EMAIL_ANALYSIS: "email_received",
    EvidenceType.FILE_ANALYSIS: "file_analyzed",
    EvidenceType.HUNT_FINDING: "log_event",
    EvidenceType.IOC_MATCH: "ioc_detected",
    EvidenceType.THREAT_INTEL: "ioc_detected",
}


def build_timeline(
    evidence_list: list[Evidence],
    correlations: list[CorrelationResult] | None = None,
) -> Timeline:
    """Build a chronological timeline from evidence and (optional) correlations."""
    if not evidence_list and not correlations:
        return Timeline()

    errors: list[str] = []
    raw_events: list[tuple[datetime, TimelineEvent]] = []

    # Index evidence by id for correlation timestamps
    by_id: dict[str, Evidence] = {ev.evidence_id: ev for ev in evidence_list}

    # 1. Evidence events
    for ev in evidence_list:
        parsed_ts = _parse_ts(ev.timestamp)
        if parsed_ts is None:
            errors.append(f"evidence {ev.evidence_id}: invalid timestamp {ev.timestamp!r}")
            continue
        event = _evidence_to_event(ev)
        raw_events.append((parsed_ts, event))

    # 2. Correlation events
    for corr in correlations or []:
        ts_str = _correlation_timestamp(corr, by_id)
        if ts_str is None:
            errors.append(f"correlation {corr.correlation_id}: no valid timestamp")
            continue
        parsed_ts = _parse_ts(ts_str)
        if parsed_ts is None:
            errors.append(
                f"correlation {corr.correlation_id}: invalid timestamp {ts_str!r}"
            )
            continue
        event = _correlation_to_event(corr, ts_str)
        raw_events.append((parsed_ts, event))

    # 3. Sort ascending by parsed timestamp
    raw_events.sort(key=lambda pair: pair[0])

    events = [event for _, event in raw_events]
    start_time = events[0].timestamp if events else None
    end_time = events[-1].timestamp if events else None

    return Timeline(
        events=events,
        start_time=start_time,
        end_time=end_time,
        event_count=len(events),
        errors=errors,
    )


# ---------- event builders ----------
def _evidence_to_event(ev: Evidence) -> TimelineEvent:
    event_type = _EVENT_TYPE_BY_EVIDENCE.get(ev.evidence_type, "log_event")
    severity = _severity_from_confidence(ev.confidence)
    related = _iocs_from_provenance(ev.provenance)
    return TimelineEvent(
        event_id=f"te-{_hash_id(ev.evidence_id)}",
        timestamp=ev.timestamp,
        description=ev.finding,
        source_module=ev.source_module,
        evidence_reference=ev.evidence_id,
        severity=severity,
        event_type=event_type,
        related_iocs=related,
    )


def _correlation_to_event(
    corr: CorrelationResult, timestamp: str
) -> TimelineEvent:
    return TimelineEvent(
        event_id=f"te-{_hash_id(corr.correlation_id)}",
        timestamp=timestamp,
        description=corr.detail,
        source_module="investigation",
        evidence_reference=corr.evidence_a,
        severity="medium",
        event_type="correlation",
        related_iocs=list(corr.shared_indicators),
    )


def _correlation_timestamp(
    corr: CorrelationResult, by_id: dict[str, Evidence]
) -> str | None:
    """Use the earlier of the two evidence timestamps."""
    a = by_id.get(corr.evidence_a)
    b = by_id.get(corr.evidence_b)
    ts_a = a.timestamp if a else None
    ts_b = b.timestamp if b else None
    if ts_a and ts_b:
        # ISO strings sort lexicographically; earlier wins
        return ts_a if ts_a <= ts_b else ts_b
    return ts_a or ts_b


# ---------- helpers ----------
def _severity_from_confidence(confidence: int) -> str:
    if confidence >= 70:
        return "high"
    if confidence >= 40:
        return "medium"
    return "low"


def _iocs_from_provenance(prov: dict | None) -> list[str]:
    if not prov:
        return []
    out: list[str] = []
    single = prov.get("ioc_value")
    if isinstance(single, str) and single:
        out.append(single)
    multi = prov.get("ioc_list")
    if isinstance(multi, list):
        for item in multi:
            if isinstance(item, str) and item and item not in out:
                out.append(item)
    return out


def _hash_id(value: str) -> str:
    return hashlib.sha1(value.encode()).hexdigest()[:12]


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None
