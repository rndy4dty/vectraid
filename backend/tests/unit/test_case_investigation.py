"""Phase 8e - Case + Investigation integration tests (test-first)."""

from app.modules.investigation.case import (
    CasePriority,
    CaseStatus,
    new_case,
)
from app.modules.investigation.case_evidence import list_evidence_ids
from app.modules.investigation.case_investigation import (
    CaseReport,
    open_case_investigation,
)
from app.modules.investigation.evidence import (
    Evidence,
    EvidenceStore,
    EvidenceType,
)


def _make_case():
    return new_case(
        case_id="CASE-2026-0001",
        title="Test investigation",
        priority=CasePriority.HIGH,
        created_by="analyst@example.com",
    )


def _make_store_with_evidence() -> EvidenceStore:
    store = EvidenceStore()
    store.add(
        Evidence(
            evidence_id="ev-001",
            case_id="CASE-2026-0001",
            source_module="phishtrace",
            evidence_type=EvidenceType.EMAIL_ANALYSIS,
            raw_reference="raw:001",
            finding="Phishing email detected",
            timestamp="2026-11-01T08:00:00Z",
            confidence=85,
            provenance={
                "ioc_value": "evil.test",
                "ioc_list": ["evil.test", "203.0.113.10"],
                "finding_code": "display_name_brand_mismatch",
            },
        )
    )
    store.add(
        Evidence(
            evidence_id="ev-002",
            case_id="CASE-2026-0001",
            source_module="huntscope",
            evidence_type=EvidenceType.HUNT_FINDING,
            raw_reference="raw:002",
            finding="Encoded PowerShell detected",
            timestamp="2026-11-01T09:00:00Z",
            confidence=80,
            provenance={
                "ioc_value": "203.0.113.10",
                "rule_id": "process_powershell_encoded",
            },
        )
    )
    return store


# ---------- dataclass shape ----------
def test_case_report_fields():
    case = _make_case()
    store = _make_store_with_evidence()
    r = open_case_investigation(case, store)
    assert isinstance(r, CaseReport)
    assert r.case is not None
    assert r.investigation is not None


# ---------- basic flow ----------
def test_open_case_investigation_returns_report():
    case = _make_case()
    store = _make_store_with_evidence()
    report = open_case_investigation(case, store)
    assert report.investigation.summary.evidence_count == 2


def test_open_case_investigation_links_evidence():
    case = _make_case()
    store = _make_store_with_evidence()
    report = open_case_investigation(case, store)
    linked = list_evidence_ids(report.case)
    assert "ev-001" in linked
    assert "ev-002" in linked


def test_open_case_investigation_transitions_status():
    """Opening an investigation should move the case to INVESTIGATING."""
    case = _make_case()
    store = _make_store_with_evidence()
    report = open_case_investigation(case, store)
    assert report.case.status == CaseStatus.INVESTIGATING


def test_open_case_investigation_does_not_re_transition():
    """Calling twice should not error on status transition."""
    case = _make_case()
    store = _make_store_with_evidence()
    report1 = open_case_investigation(case, store)
    # second call on already-investigating case
    report2 = open_case_investigation(report1.case, store)
    assert report2.case.status == CaseStatus.INVESTIGATING


# ---------- evidence filtering ----------
def test_evidence_from_other_cases_ignored():
    """Only evidence matching the case_id is investigated."""
    case = _make_case()
    store = _make_store_with_evidence()
    # Add evidence with different case_id
    store.add(
        Evidence(
            evidence_id="ev-999",
            case_id="CASE-OTHER",
            source_module="phishtrace",
            evidence_type=EvidenceType.EMAIL_ANALYSIS,
            raw_reference="raw:999",
            finding="Other case",
            timestamp="2026-11-01T07:00:00Z",
            confidence=80,
            provenance={},
        )
    )
    report = open_case_investigation(case, store)
    # Only ev-001 and ev-002 investigated
    assert report.investigation.summary.evidence_count == 2
    # ev-999 not linked
    assert "ev-999" not in list_evidence_ids(report.case)


# ---------- MITRE and risk propagate ----------
def test_mitre_from_investigation():
    case = _make_case()
    store = _make_store_with_evidence()
    report = open_case_investigation(case, store)
    ids = {m.technique_id for m in report.investigation.mitre_mappings}
    assert "T1566.002" in ids
    assert "T1059.001" in ids


def test_risk_from_investigation():
    case = _make_case()
    store = _make_store_with_evidence()
    report = open_case_investigation(case, store)
    assert report.investigation.summary.risk_score > 0
    assert report.investigation.summary.risk_classification in {
        "low", "medium", "high", "critical"
    }


# ---------- empty case ----------
def test_empty_case_investigation():
    case = _make_case()
    store = EvidenceStore()
    report = open_case_investigation(case, store)
    assert report.investigation.summary.evidence_count == 0
    # Case remains NEW (no evidence to investigate -> no transition)
    assert report.case.status == CaseStatus.NEW


# ---------- audit trail ----------
def test_audit_trail_records_evidence_linking():
    case = _make_case()
    store = _make_store_with_evidence()
    report = open_case_investigation(case, store)
    actions = [e.action for e in report.case.history]
    assert "evidence_linked" in actions


def test_audit_trail_records_status_transition():
    case = _make_case()
    store = _make_store_with_evidence()
    report = open_case_investigation(case, store)
    actions = [e.action for e in report.case.history]
    assert "status_changed" in actions
