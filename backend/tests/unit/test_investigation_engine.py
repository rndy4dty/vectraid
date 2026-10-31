"""Phase 7f - Investigation Engine tests (test-first)."""
from app.modules.investigation.engine import (
    InvestigationReport,
    InvestigationSummary,
    run_investigation,
)
from app.modules.investigation.evidence import Evidence, EvidenceType


def _ev(
    eid: str = "ev-001",
    module: str = "phishtrace",
    evidence_type: EvidenceType = EvidenceType.EMAIL_ANALYSIS,
    timestamp: str = "2026-11-01T09:00:00Z",
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
def test_summary_shape():
    s = InvestigationSummary(
        evidence_count=1,
        correlation_count=0,
        mitre_technique_count=0,
        risk_classification="low",
        risk_score=10.0,
        timeline_event_count=1,
        modules_involved=["phishtrace"],
        unique_iocs=1,
        errors=[],
    )
    assert s.evidence_count == 1
    assert s.modules_involved == ["phishtrace"]


def test_report_shape():
    r = run_investigation([], case_id="case-001")
    assert isinstance(r, InvestigationReport)
    assert r.case_id == "case-001"
    assert isinstance(r.summary, InvestigationSummary)


# ---------- empty case ----------
def test_empty_case_produces_insufficient_data():
    r = run_investigation([], case_id="case-001")
    assert r.summary.evidence_count == 0
    assert r.summary.risk_classification == "insufficient_data"
    assert r.summary.risk_score == 0.0
    assert r.summary.timeline_event_count == 0


# ---------- single evidence ----------
def test_single_evidence_investigation():
    ev = _ev(
        module="huntscope",
        evidence_type=EvidenceType.HUNT_FINDING,
        provenance={"rule_id": "process_powershell_encoded",
                    "ioc_value": "203.0.113.10"},
    )
    r = run_investigation([ev], case_id="case-001")
    assert r.summary.evidence_count == 1
    assert r.summary.risk_classification in {
        "informational", "low", "medium", "high", "critical"
    }
    assert r.summary.risk_score > 0
    assert r.summary.timeline_event_count == 1


# ---------- MITRE techniques detected ----------
def test_mitre_techniques_present():
    ev = _ev(
        module="huntscope",
        evidence_type=EvidenceType.HUNT_FINDING,
        provenance={"rule_id": "process_powershell_encoded"},
    )
    r = run_investigation([ev], case_id="case-001")
    assert r.summary.mitre_technique_count >= 1
    technique_ids = {m.technique_id for m in r.mitre_mappings}
    assert "T1059.001" in technique_ids


# ---------- correlations across modules ----------
def test_correlations_between_modules():
    ev1 = _ev(
        "ev-001", module="phishtrace", evidence_type=EvidenceType.EMAIL_ANALYSIS,
        provenance={"ioc_value": "evil.test"},
    )
    ev2 = _ev(
        "ev-002", module="huntscope", evidence_type=EvidenceType.HUNT_FINDING,
        provenance={"ioc_value": "evil.test", "rule_id": "process_powershell_encoded"},
    )
    r = run_investigation([ev1, ev2], case_id="case-001")
    assert r.summary.correlation_count >= 1
    assert "phishtrace" in r.summary.modules_involved
    assert "huntscope" in r.summary.modules_involved


# ---------- unique iocs ----------
def test_unique_iocs_count():
    ev1 = _ev("ev-001", provenance={"ioc_value": "evil.test"})
    ev2 = _ev("ev-002", module="huntscope",
              evidence_type=EvidenceType.HUNT_FINDING,
              provenance={"ioc_value": "evil.test"})
    ev3 = _ev("ev-003", module="maltrace",
              evidence_type=EvidenceType.FILE_ANALYSIS,
              provenance={"ioc_value": "203.0.113.10"})
    r = run_investigation([ev1, ev2, ev3], case_id="case-001")
    # evil.test and 203.0.113.10 -> 2 unique
    assert r.summary.unique_iocs == 2


# ---------- timeline integration ----------
def test_timeline_has_all_events():
    ev1 = _ev("ev-001", timestamp="2026-11-01T08:00:00Z")
    ev2 = _ev("ev-002", module="maltrace",
              evidence_type=EvidenceType.FILE_ANALYSIS,
              timestamp="2026-11-01T10:00:00Z")
    r = run_investigation([ev1, ev2], case_id="case-001")
    assert r.summary.timeline_event_count >= 2


# ---------- risk uses case aggregation ----------
def test_case_risk_high_with_critical_evidence():
    ev = _ev(
        module="maltrace",
        evidence_type=EvidenceType.FILE_ANALYSIS,
        confidence=95,
        provenance={"verdict": "malicious", "ioc_value": "c" * 64},
    )
    r = run_investigation([ev], case_id="case-001")
    # Malicious file with 95 confidence should produce at least medium risk
    assert r.summary.risk_classification in {"medium", "high", "critical"}


# ---------- errors propagated ----------
def test_errors_collected_from_components():
    # Invalid timestamp -> error in timeline
    ev = _ev(timestamp="not-a-timestamp")
    r = run_investigation([ev], case_id="case-001")
    assert len(r.summary.errors) >= 1


# ---------- case_id propagation ----------
def test_case_id_propagates():
    r = run_investigation([_ev()], case_id="case-XYZ")
    assert r.case_id == "case-XYZ"
