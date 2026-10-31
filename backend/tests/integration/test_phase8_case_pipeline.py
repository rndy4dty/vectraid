"""Phase 8 integration - end-to-end Case Management pipeline.

Simulates: analyst creates a case, evidence is added, investigation runs,
analyst records a decision, and the case is eventually closed.

All data is synthetic; no network.
"""
from app.modules.investigation.case import (
    CasePriority,
    CaseStatus,
    new_case,
    transition_status,
)
from app.modules.investigation.case_decisions import (
    DecisionOutcome,
    add_decision,
    latest_decision,
    list_decisions,
)
from app.modules.investigation.case_evidence import (
    has_evidence,
    list_evidence_ids,
)
from app.modules.investigation.case_investigation import (
    open_case_investigation,
)
from app.modules.investigation.evidence import (
    Evidence,
    EvidenceStore,
    EvidenceType,
)


def _build_full_store() -> EvidenceStore:
    store = EvidenceStore()
    store.add(
        Evidence(
            evidence_id="phish-001",
            case_id="CASE-2026-0001",
            source_module="phishtrace",
            evidence_type=EvidenceType.EMAIL_ANALYSIS,
            raw_reference="evidence:phishtrace:phish-001",
            finding="Phishing email with brand mismatch",
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
            evidence_id="mal-001",
            case_id="CASE-2026-0001",
            source_module="maltrace",
            evidence_type=EvidenceType.FILE_ANALYSIS,
            raw_reference="evidence:maltrace:mal-001",
            finding="Malicious file with injection strings",
            timestamp="2026-11-01T08:30:00Z",
            confidence=90,
            provenance={
                "ioc_value": "c" * 64,
                "ioc_list": ["c" * 64, "203.0.113.10"],
                "verdict": "malicious",
            },
        )
    )
    store.add(
        Evidence(
            evidence_id="hunt-001",
            case_id="CASE-2026-0001",
            source_module="huntscope",
            evidence_type=EvidenceType.HUNT_FINDING,
            raw_reference="evidence:huntscope:hunt-001",
            finding="Encoded PowerShell on endpoint",
            timestamp="2026-11-01T09:00:00Z",
            confidence=80,
            provenance={
                "ioc_value": "203.0.113.10",
                "rule_id": "process_powershell_encoded",
                "hostname": "wks-01",
            },
        )
    )
    return store


# ---------- end-to-end ----------
def test_full_case_lifecycle():
    # 1. Analyst creates a case
    case = new_case(
        case_id="CASE-2026-0001",
        title="Suspicious phishing with malware",
        priority=CasePriority.HIGH,
        created_by="analyst@example.com",
    )
    assert case.status == CaseStatus.NEW
    assert len(case.history) == 1

    # 2. Evidence is added to the store (from modules)
    store = _build_full_store()

    # 3. Investigation runs
    report = open_case_investigation(case, store, by="analyst@example.com")
    investigating_case = report.case

    # 3a. Status transitioned to INVESTIGATING
    assert investigating_case.status == CaseStatus.INVESTIGATING

    # 3b. All evidence linked
    linked = list_evidence_ids(investigating_case)
    assert set(linked) == {"phish-001", "mal-001", "hunt-001"}

    # 3c. Investigation has findings
    inv = report.investigation
    assert inv.summary.evidence_count == 3
    assert inv.summary.correlation_count >= 1
    assert inv.summary.mitre_technique_count >= 2
    assert inv.summary.timeline_event_count >= 3
    assert inv.summary.risk_classification in {"medium", "high", "critical"}

    # 3d. MITRE techniques
    ids = {m.technique_id for m in inv.mitre_mappings}
    assert "T1059.001" in ids  # PowerShell
    assert "T1204.002" in ids  # Malicious file
    assert "T1566.002" in ids  # Spearphishing link

    # 4. Analyst records a decision
    decided_case = add_decision(
        investigating_case,
        outcome=DecisionOutcome.ESCALATE,
        rationale="Multiple malicious indicators; escalate to IR team",
        by="analyst@example.com",
    )
    assert len(decided_case.decisions) == 1
    assert latest_decision(decided_case).outcome == DecisionOutcome.ESCALATE

    # 5. Transition to RESOLVED then CLOSED
    resolved_case = transition_status(
        decided_case, CaseStatus.RESOLVED, by="analyst@example.com"
    )
    closed_case = transition_status(
        resolved_case, CaseStatus.CLOSED, by="lead@example.com"
    )
    assert closed_case.status == CaseStatus.CLOSED

    # 6. Audit trail captures everything
    actions = [e.action for e in closed_case.history]
    assert actions[0] == "created"
    assert "status_changed" in actions
    assert "evidence_linked" in actions
    assert "decision_added" in actions


# ---------- idempotency ----------
def test_reopening_investigation_is_idempotent():
    case = new_case(
        case_id="CASE-2026-0001",
        title="Test",
        priority=CasePriority.MEDIUM,
        created_by="analyst@example.com",
    )
    store = _build_full_store()

    r1 = open_case_investigation(case, store, by="analyst@example.com")
    r2 = open_case_investigation(r1.case, store, by="analyst@example.com")

    # No duplicate evidence linking
    assert len(list_evidence_ids(r2.case)) == len(
        list_evidence_ids(r1.case)
    )
    # Status stays INVESTIGATING
    assert r2.case.status == CaseStatus.INVESTIGATING


# ---------- empty case lifecycle ----------
def test_empty_case_can_be_closed():
    case = new_case(
        case_id="CASE-2026-0002",
        title="No evidence found",
        priority=CasePriority.LOW,
        created_by="analyst@example.com",
    )
    store = EvidenceStore()

    report = open_case_investigation(case, store, by="analyst@example.com")
    # Status stays NEW because no evidence
    assert report.case.status == CaseStatus.NEW

    # But case can be closed directly via the workflow
    # (NEW -> INVESTIGATING -> RESOLVED -> CLOSED)
    investigating = transition_status(
        report.case, CaseStatus.INVESTIGATING, by="analyst@example.com"
    )
    resolved = transition_status(
        investigating, CaseStatus.RESOLVED, by="analyst@example.com"
    )
    closed = transition_status(
        resolved, CaseStatus.CLOSED, by="analyst@example.com"
    )
    assert closed.status == CaseStatus.CLOSED


# ---------- timeline starts from earliest evidence ----------
def test_investigation_timeline_covers_all_evidence():
    case = new_case(
        case_id="CASE-2026-0001",
        title="Test",
        priority=CasePriority.HIGH,
        created_by="analyst@example.com",
    )
    store = _build_full_store()
    report = open_case_investigation(case, store)

    ts = [e.timestamp for e in report.investigation.timeline.events]
    # Earliest evidence should be at 2026-11-01T08:00:00Z
    assert report.investigation.timeline.start_time is not None
    # Timeline is sorted ascending
    assert ts == sorted(ts)


# ---------- multiple cases isolation ----------
def test_evidence_from_other_cases_isolated():
    # case_a uses the same case_id as the fixture evidence so phish-001
    # is eligible; other-001 uses a different case_id and must be excluded.
    case_a = new_case(
        case_id="CASE-2026-0001", title="A",
        priority=CasePriority.MEDIUM, created_by="a@x.com",
    )
    store = _build_full_store()
    # Add evidence for CASE-B
    store.add(
        Evidence(
            evidence_id="other-001",
            case_id="CASE-B",
            source_module="phishtrace",
            evidence_type=EvidenceType.EMAIL_ANALYSIS,
            raw_reference="raw:other",
            finding="Other case",
            timestamp="2026-11-01T07:00:00Z",
            confidence=80,
            provenance={},
        )
    )

    report = open_case_investigation(case_a, store)
    linked = list_evidence_ids(report.case)
    assert "other-001" not in linked
    assert has_evidence(report.case, "phish-001") is True


# ---------- decision records evidence reference ----------
def test_decision_with_evidence_reference():
    case = new_case(
        case_id="CASE-2026-0001",
        title="Test",
        priority=CasePriority.HIGH,
        created_by="analyst@example.com",
    )
    store = _build_full_store()
    report = open_case_investigation(case, store)

    decided = add_decision(
        report.case,
        outcome=DecisionOutcome.RESOLVED,
        rationale="Malicious file confirmed via static analysis",
        by="analyst@example.com",
        evidence_reference="mal-001",
    )
    decisions = list_decisions(decided)
    assert decisions[-1].evidence_reference == "mal-001"
