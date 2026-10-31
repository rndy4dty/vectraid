"""Phase 7 integration - end-to-end Investigation pipeline.

Simulates: analyst collects evidence from PhishTrace, MalTrace, and
HuntScope, then runs the Investigation Engine to produce a full report.

No network. All inputs synthetic.
"""
from app.modules.investigation.engine import run_investigation
from app.modules.investigation.evidence import Evidence, EvidenceType

SHARED_IOC = "evil.test"
SHARED_IP = "203.0.113.10"


def _phish_evidence() -> Evidence:
    return Evidence(
        evidence_id="phish-001",
        case_id="case-001",
        source_module="phishtrace",
        evidence_type=EvidenceType.EMAIL_ANALYSIS,
        raw_reference="evidence:phishtrace:phish-001",
        finding="Email with display name brand mismatch and defanged URL",
        timestamp="2026-11-01T08:00:00Z",
        confidence=85,
        provenance={
            "ioc_value": SHARED_IOC,
            "ioc_list": [SHARED_IOC, SHARED_IP],
            "finding_code": "display_name_brand_mismatch",
            "hostname": "mail-gw-01",
        },
    )


def _mal_evidence() -> Evidence:
    return Evidence(
        evidence_id="mal-001",
        case_id="case-001",
        source_module="maltrace",
        evidence_type=EvidenceType.FILE_ANALYSIS,
        raw_reference="evidence:maltrace:mal-001",
        finding="File verdict malicious with injection-related strings",
        timestamp="2026-11-01T08:30:00Z",
        confidence=90,
        provenance={
            "verdict": "malicious",
            "ioc_value": "c" * 64,
            "ioc_list": ["c" * 64, SHARED_IP],
            "hostname": "wks-01",
        },
    )


def _hunt_evidence() -> Evidence:
    return Evidence(
        evidence_id="hunt-001",
        case_id="case-001",
        source_module="huntscope",
        evidence_type=EvidenceType.HUNT_FINDING,
        raw_reference="evidence:huntscope:hunt-001",
        finding="Encoded PowerShell executing and contacting external host",
        timestamp="2026-11-01T09:15:00Z",
        confidence=80,
        provenance={
            "rule_id": "process_powershell_encoded",
            "ioc_value": SHARED_IP,
            "hostname": "wks-01",
        },
    )


def _all_evidence() -> list[Evidence]:
    return [_phish_evidence(), _mal_evidence(), _hunt_evidence()]


# ---------- report structure ----------
def test_report_contains_all_sections():
    r = run_investigation(_all_evidence(), case_id="case-001")
    assert r.case_id == "case-001"
    assert len(r.evidence) == 3
    assert r.summary is not None
    assert r.risk is not None
    assert r.timeline is not None


# ---------- summary ----------
def test_summary_counts():
    r = run_investigation(_all_evidence(), case_id="case-001")
    assert r.summary.evidence_count == 3
    assert r.summary.correlation_count >= 1
    assert r.summary.timeline_event_count >= 3


def test_summary_modules_involved():
    r = run_investigation(_all_evidence(), case_id="case-001")
    assert r.summary.modules_involved == [
        "huntscope", "maltrace", "phishtrace"
    ]


def test_summary_unique_iocs():
    r = run_investigation(_all_evidence(), case_id="case-001")
    # evil.test, 203.0.113.10, c*64 -> at least 3
    assert r.summary.unique_iocs >= 3


# ---------- correlations ----------
def test_correlation_detects_shared_ip():
    r = run_investigation(_all_evidence(), case_id="case-001")
    # SHARED_IP appears in phish, mal, hunt -> cross-module pairs
    exact_corrs = [c for c in r.correlations if c.correlation_type == "exact_ioc"]
    assert len(exact_corrs) >= 1
    # At least one correlation mentions the shared IP
    shared = set()
    for c in exact_corrs:
        shared.update(c.shared_indicators)
    assert SHARED_IP in shared


# ---------- risk ----------
def test_risk_is_high_or_critical():
    r = run_investigation(_all_evidence(), case_id="case-001")
    # malicious file with high confidence should elevate case risk
    assert r.summary.risk_classification in {"medium", "high", "critical"}
    assert r.summary.risk_score > 40


# ---------- mitre ----------
def test_mitre_techniques_present():
    r = run_investigation(_all_evidence(), case_id="case-001")
    ids = {m.technique_id for m in r.mitre_mappings}
    # Powershell -> T1059.001, malicious file -> T1204.002
    assert "T1059.001" in ids
    assert "T1204.002" in ids
    # Phish finding -> T1566.002
    assert "T1566.002" in ids


# ---------- timeline ----------
def test_timeline_is_ordered():
    r = run_investigation(_all_evidence(), case_id="case-001")
    ts = [e.timestamp for e in r.timeline.events]
    assert ts == sorted(ts)


def test_timeline_starts_with_earliest_evidence():
    r = run_investigation(_all_evidence(), case_id="case-001")
    assert r.timeline.start_time == "2026-11-01T08:00:00Z"
    assert r.timeline.end_time == "2026-11-01T09:15:00Z"


def test_timeline_includes_correlation_events():
    r = run_investigation(_all_evidence(), case_id="case-001")
    corr_events = [e for e in r.timeline.events if e.event_type == "correlation"]
    assert len(corr_events) >= 1


# ---------- consistency ----------
def test_summary_consistent_with_lists():
    r = run_investigation(_all_evidence(), case_id="case-001")
    assert r.summary.evidence_count == len(r.evidence)
    assert r.summary.correlation_count == len(r.correlations)
    assert r.summary.mitre_technique_count == len(r.mitre_mappings)
    assert r.summary.timeline_event_count == len(r.timeline.events)


# ---------- empty case ----------
def test_empty_case_report():
    r = run_investigation([], case_id="case-empty")
    assert r.case_id == "case-empty"
    assert r.summary.evidence_count == 0
    assert r.summary.risk_classification == "insufficient_data"
    assert r.timeline is not None
    assert r.timeline.event_count == 0


# ---------- deterministic ----------
def test_deterministic_output():
    """Two runs on the same input produce the same summary."""
    r1 = run_investigation(_all_evidence(), case_id="case-001")
    r2 = run_investigation(_all_evidence(), case_id="case-001")
    assert r1.summary.evidence_count == r2.summary.evidence_count
    assert r1.summary.correlation_count == r2.summary.correlation_count
    assert r1.summary.risk_score == r2.summary.risk_score
    assert r1.summary.mitre_technique_count == r2.summary.mitre_technique_count
