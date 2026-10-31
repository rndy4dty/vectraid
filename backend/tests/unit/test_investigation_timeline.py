"""Phase 7e - Timeline tests (test-first)."""
from app.modules.investigation.correlation import CorrelationResult
from app.modules.investigation.evidence import Evidence, EvidenceType
from app.modules.investigation.timeline import (
    Timeline,
    TimelineEvent,
    build_timeline,
)


def _ev(
    eid: str = "ev-001",
    timestamp: str = "2026-11-01T09:00:00Z",
    module: str = "phishtrace",
    evidence_type: EvidenceType = EvidenceType.EMAIL_ANALYSIS,
    confidence: int = 80,
    finding: str = "test finding",
    provenance: dict | None = None,
) -> Evidence:
    return Evidence(
        evidence_id=eid,
        case_id="case-001",
        source_module=module,
        evidence_type=evidence_type,
        raw_reference=f"raw:{eid}",
        finding=finding,
        timestamp=timestamp,
        confidence=confidence,
        provenance=provenance or {},
    )


# ---------- dataclass shapes ----------
def test_timeline_event_fields():
    e = TimelineEvent(
        event_id="te-001",
        timestamp="2026-11-01T09:00:00Z",
        description="Email received",
        source_module="phishtrace",
        evidence_reference="ev-001",
        severity="medium",
        event_type="email_received",
        related_iocs=["evil.test"],
    )
    assert e.event_id == "te-001"
    assert e.event_type == "email_received"
    assert e.related_iocs == ["evil.test"]


def test_timeline_shape():
    t = Timeline(
        events=[],
        start_time=None,
        end_time=None,
        event_count=0,
        errors=[],
    )
    assert t.events == []
    assert t.event_count == 0


# ---------- basic timeline ----------
def test_timeline_from_single_evidence():
    ev = _ev()
    t = build_timeline([ev])
    assert t.event_count == 1
    assert t.events[0].evidence_reference == "ev-001"
    assert t.start_time == "2026-11-01T09:00:00Z"
    assert t.end_time == "2026-11-01T09:00:00Z"


def test_timeline_sorted_ascending():
    ev1 = _ev("ev-001", timestamp="2026-11-01T11:00:00Z")
    ev2 = _ev("ev-002", timestamp="2026-11-01T09:00:00Z")
    ev3 = _ev("ev-003", timestamp="2026-11-01T10:00:00Z")
    t = build_timeline([ev1, ev2, ev3])
    timestamps = [e.timestamp for e in t.events]
    assert timestamps == [
        "2026-11-01T09:00:00Z",
        "2026-11-01T10:00:00Z",
        "2026-11-01T11:00:00Z",
    ]


def test_timeline_start_and_end():
    ev1 = _ev("ev-001", timestamp="2026-11-01T08:00:00Z")
    ev2 = _ev("ev-002", timestamp="2026-11-01T12:00:00Z")
    t = build_timeline([ev1, ev2])
    assert t.start_time == "2026-11-01T08:00:00Z"
    assert t.end_time == "2026-11-01T12:00:00Z"


# ---------- event type from evidence_type ----------
def test_event_type_from_email_evidence():
    ev = _ev(evidence_type=EvidenceType.EMAIL_ANALYSIS)
    t = build_timeline([ev])
    assert t.events[0].event_type == "email_received"


def test_event_type_from_file_evidence():
    ev = _ev(module="maltrace", evidence_type=EvidenceType.FILE_ANALYSIS)
    t = build_timeline([ev])
    assert t.events[0].event_type == "file_analyzed"


def test_event_type_from_hunt_evidence():
    ev = _ev(module="huntscope", evidence_type=EvidenceType.HUNT_FINDING)
    t = build_timeline([ev])
    assert t.events[0].event_type == "log_event"


def test_event_type_from_ioc_match():
    ev = _ev(module="intelfusion", evidence_type=EvidenceType.IOC_MATCH)
    t = build_timeline([ev])
    assert t.events[0].event_type == "ioc_detected"


# ---------- severity from confidence ----------
def test_severity_from_confidence_low():
    ev = _ev(confidence=20)
    t = build_timeline([ev])
    assert t.events[0].severity == "low"


def test_severity_from_confidence_high():
    ev = _ev(confidence=85)
    t = build_timeline([ev])
    assert t.events[0].severity == "high"


def test_severity_from_confidence_medium():
    ev = _ev(confidence=55)
    t = build_timeline([ev])
    assert t.events[0].severity == "medium"


# ---------- related IOCs ----------
def test_related_iocs_populated():
    ev = _ev(provenance={"ioc_value": "evil.test"})
    t = build_timeline([ev])
    assert "evil.test" in t.events[0].related_iocs


def test_related_iocs_list():
    ev = _ev(provenance={"ioc_list": ["evil.test", "203.0.113.10"]})
    t = build_timeline([ev])
    assert set(t.events[0].related_iocs) == {"evil.test", "203.0.113.10"}


# ---------- correlations become events ----------
def test_correlations_add_events():
    ev1 = _ev("ev-001", provenance={"ioc_value": "evil.test"})
    ev2 = _ev("ev-002", provenance={"ioc_value": "evil.test"})
    corr = CorrelationResult(
        correlation_id="cor-001",
        evidence_a="ev-001",
        evidence_b="ev-002",
        correlation_type="exact_ioc",
        strength=90,
        detail="both mention evil.test",
        shared_indicators=["evil.test"],
    )
    t = build_timeline([ev1, ev2], correlations=[corr])
    # Correlation events are added
    corr_events = [e for e in t.events if e.event_type == "correlation"]
    assert len(corr_events) == 1
    # Total events = 2 evidence + 1 correlation
    assert t.event_count == 3


# ---------- invalid timestamps ----------
def test_invalid_timestamp_collected_as_error():
    ev = _ev(timestamp="not-a-timestamp")
    t = build_timeline([ev])
    # The bad event is skipped, not crashed
    assert t.event_count == 0
    assert len(t.errors) >= 1


def test_mixed_valid_and_invalid():
    ev1 = _ev("ev-001", timestamp="2026-11-01T09:00:00Z")
    ev2 = _ev("ev-002", timestamp="invalid")
    t = build_timeline([ev1, ev2])
    assert t.event_count == 1
    assert len(t.errors) >= 1


# ---------- empty ----------
def test_empty_evidence_empty_timeline():
    t = build_timeline([])
    assert t.event_count == 0
    assert t.start_time is None
    assert t.end_time is None
