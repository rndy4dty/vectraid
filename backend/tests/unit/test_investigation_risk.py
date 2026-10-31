"""Phase 7c - Risk Assessment tests (test-first)."""
import pytest

from app.modules.investigation.evidence import Evidence, EvidenceType
from app.modules.investigation.risk import (
    RiskParameters,
    RiskScore,
    assess_case,
    assess_evidence,
    compute_risk,
)


# ---------- RiskParameters validation ----------
def test_risk_parameters_fields():
    p = RiskParameters(
        severity=80, confidence=70, reputation=60,
        evidence_quality=50, exposure=40,
    )
    assert p.severity == 80
    assert p.confidence == 70


def test_risk_parameters_reject_out_of_range():
    with pytest.raises(ValueError):
        RiskParameters(
            severity=150, confidence=70, reputation=60,
            evidence_quality=50, exposure=40,
        )
    with pytest.raises(ValueError):
        RiskParameters(
            severity=-1, confidence=70, reputation=60,
            evidence_quality=50, exposure=40,
        )


# ---------- RiskScore shape ----------
def test_risk_score_fields():
    r = RiskScore(
        score=75.0,
        classification="high",
        breakdown={"severity": 80.0},
        reasons=["test"],
    )
    assert r.score == 75.0
    assert r.classification == "high"


# ---------- compute_risk ----------
def test_compute_risk_weighted_sum():
    """Verify weights: 0.30S + 0.25C + 0.20R + 0.15E + 0.10X."""
    p = RiskParameters(
        severity=100, confidence=100, reputation=100,
        evidence_quality=100, exposure=100,
    )
    r = compute_risk(p)
    assert r.score == pytest.approx(100.0)
    assert r.classification == "critical"


def test_compute_risk_all_zero():
    p = RiskParameters(
        severity=0, confidence=0, reputation=0,
        evidence_quality=0, exposure=0,
    )
    r = compute_risk(p)
    assert r.score == pytest.approx(0.0)
    assert r.classification == "informational"


def test_compute_risk_mixed():
    """S=100, C=0, R=0, E=0, X=0 -> 30."""
    p = RiskParameters(
        severity=100, confidence=0, reputation=0,
        evidence_quality=0, exposure=0,
    )
    r = compute_risk(p)
    assert r.score == pytest.approx(30.0)
    assert r.classification == "low"


def test_compute_risk_classification_bands():
    # informational: 0-19
    p = RiskParameters(severity=30, confidence=10, reputation=10, evidence_quality=10, exposure=0)
    assert compute_risk(p).classification == "informational"
    # low: 20-39
    p = RiskParameters(severity=60, confidence=20, reputation=20, evidence_quality=20, exposure=0)
    assert compute_risk(p).classification == "low"
    # medium: 40-59
    p = RiskParameters(severity=80, confidence=40, reputation=40, evidence_quality=40, exposure=20)
    assert compute_risk(p).classification == "medium"
    # high: 60-79
    p = RiskParameters(severity=100, confidence=70, reputation=60, evidence_quality=50, exposure=40)
    assert compute_risk(p).classification == "high"
    # critical: 80-100
    p = RiskParameters(
        severity=100, confidence=100, reputation=100,
        evidence_quality=100, exposure=100,
    )
    assert compute_risk(p).classification == "critical"


def test_compute_risk_breakdown_populated():
    p = RiskParameters(
        severity=50, confidence=60, reputation=70,
        evidence_quality=80, exposure=90,
    )
    r = compute_risk(p)
    assert "severity" in r.breakdown
    assert "confidence" in r.breakdown
    assert "reputation" in r.breakdown
    assert "evidence_quality" in r.breakdown
    assert "exposure" in r.breakdown
    # breakdown should match weighted contributions
    assert r.breakdown["severity"] == pytest.approx(50 * 0.30)


def test_compute_risk_reasons_populated():
    p = RiskParameters(
        severity=100, confidence=80, reputation=0,
        evidence_quality=50, exposure=0,
    )
    r = compute_risk(p)
    assert len(r.reasons) > 0
    assert any("severity" in reason.lower() for reason in r.reasons)


# ---------- assess_evidence ----------
def _ev(
    evidence_type: EvidenceType = EvidenceType.EMAIL_ANALYSIS,
    confidence: int = 80,
    module: str = "phishtrace",
    provenance: dict | None = None,
) -> Evidence:
    return Evidence(
        evidence_id="ev-001",
        case_id="case-001",
        source_module=module,
        evidence_type=evidence_type,
        raw_reference="raw:001",
        finding="f",
        timestamp="2026-11-01T09:00:00Z",
        confidence=confidence,
        provenance=provenance or {},
    )


def test_assess_evidence_produces_score():
    ev = _ev()
    r = assess_evidence(ev)
    assert 0 <= r.score <= 100
    assert r.classification in {
        "informational", "low", "medium", "high", "critical", "insufficient_data"
    }
    assert len(r.reasons) > 0


def test_assess_evidence_type_affects_severity():
    """File analysis with high confidence should score higher than hunt finding."""
    file_ev = _ev(EvidenceType.FILE_ANALYSIS, confidence=90, module="maltrace")
    hunt_ev = _ev(EvidenceType.HUNT_FINDING, confidence=90, module="huntscope")
    file_risk = assess_evidence(file_ev)
    hunt_risk = assess_evidence(hunt_ev)
    assert file_risk.score > hunt_risk.score


def test_assess_evidence_confidence_affects_score():
    low = _ev(confidence=20)
    high = _ev(confidence=90)
    assert assess_evidence(high).score > assess_evidence(low).score


# ---------- assess_case ----------
def test_assess_case_single_evidence():
    ev = _ev()
    r = assess_case([ev])
    assert 0 <= r.score <= 100
    assert r.classification in {
        "informational", "low", "medium", "high", "critical", "insufficient_data"
    }


def test_assess_case_takes_max_not_average():
    """One critical evidence should dominate several low ones."""
    critical_ev = _ev(EvidenceType.FILE_ANALYSIS, confidence=100, module="maltrace")
    low_evs = [
        _ev(EvidenceType.THREAT_INTEL, confidence=20, module="intelfusion")
        for _ in range(5)
    ]
    case_risk = assess_case([critical_ev] + low_evs)
    # Case risk should be at least the risk of the critical evidence
    critical_risk = assess_evidence(critical_ev)
    assert case_risk.score >= critical_risk.score


def test_assess_case_empty_returns_insufficient_data():
    r = assess_case([])
    assert r.classification == "insufficient_data"
    assert r.score == 0.0


def test_assess_case_breakdown_aggregated():
    ev1 = _ev(EvidenceType.FILE_ANALYSIS, confidence=80, module="maltrace")
    ev2 = _ev(EvidenceType.EMAIL_ANALYSIS, confidence=70, module="phishtrace")
    r = assess_case([ev1, ev2])
    assert "evidence_count" in r.breakdown or "max_evidence_score" in r.breakdown
    assert r.score > 0
