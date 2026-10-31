"""Investigation risk assessment - Phase 7c.

Computes an explainable risk score from five parameters, following the
VECTRAID specification:

    RiskScore = 0.30*S + 0.25*C + 0.20*R + 0.15*E + 0.10*X

Where each parameter is normalized to 0..100.

Classification bands:
    0-19   -> informational
    20-39  -> low
    40-59  -> medium
    60-79  -> high
    80-100 -> critical
    (empty case) -> insufficient_data

Design rules:
  - Every score carries a per-parameter breakdown and human-readable reasons.
  - Case risk uses max over evidence, not average: one critical indicator
    dominates many weak ones.
  - Empty case -> insufficient_data, never clean.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.modules.investigation.evidence import Evidence, EvidenceType

# ---------- weights and bands ----------
_WEIGHTS = {
    "severity": 0.30,
    "confidence": 0.25,
    "reputation": 0.20,
    "evidence_quality": 0.15,
    "exposure": 0.10,
}

_BANDS = [
    (80, "critical"),
    (60, "high"),
    (40, "medium"),
    (20, "low"),
    (0, "informational"),
]

# Severity inferred from evidence type.
_SEVERITY_BY_TYPE = {
    EvidenceType.FILE_ANALYSIS: 70,
    EvidenceType.EMAIL_ANALYSIS: 55,
    EvidenceType.HUNT_FINDING: 60,
    EvidenceType.IOC_MATCH: 50,
    EvidenceType.THREAT_INTEL: 35,
}

# Reputation is inferred from module provenance where available; otherwise
# a neutral 50. We deliberately do not invent reputation.
_NEUTRAL_REPUTATION = 50


@dataclass(frozen=True)
class RiskParameters:
    severity: int
    confidence: int
    reputation: int
    evidence_quality: int
    exposure: int

    def __post_init__(self) -> None:
        for name in (
            "severity", "confidence", "reputation",
            "evidence_quality", "exposure",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{name} must be an int")
            if not (0 <= value <= 100):
                raise ValueError(f"{name} must be 0..100, got {value}")


@dataclass(frozen=True)
class RiskScore:
    score: float
    classification: str
    breakdown: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)


# ---------- core ----------
def compute_risk(params: RiskParameters) -> RiskScore:
    """Compute the weighted risk score from explicit parameters."""
    breakdown: dict[str, float] = {}
    total = 0.0
    for name, weight in _WEIGHTS.items():
        value = getattr(params, name)
        contribution = value * weight
        breakdown[name] = round(contribution, 2)
        total += contribution

    score = round(total, 2)
    classification = _classify(score)
    reasons = _build_reasons(params, score, classification)

    return RiskScore(
        score=score,
        classification=classification,
        breakdown=breakdown,
        reasons=reasons,
    )


def _classify(score: float) -> str:
    for threshold, label in _BANDS:
        if score >= threshold:
            return label
    return "informational"


def _build_reasons(
    params: RiskParameters, score: float, classification: str
) -> list[str]:
    reasons: list[str] = []
    if params.severity >= 70:
        reasons.append(f"High severity ({params.severity})")
    if params.confidence >= 70:
        reasons.append(f"High confidence ({params.confidence})")
    if params.reputation >= 70:
        reasons.append(f"Poor reputation ({params.reputation})")
    if params.evidence_quality >= 70:
        reasons.append(f"Strong evidence quality ({params.evidence_quality})")
    if params.exposure >= 70:
        reasons.append(f"High exposure ({params.exposure})")
    if not reasons:
        reasons.append(f"No parameter crosses strong threshold; score {score} ({classification})")
    return reasons


# ---------- per-evidence ----------
def assess_evidence(evidence: Evidence) -> RiskScore:
    """Assess a single evidence item."""
    severity = _SEVERITY_BY_TYPE.get(evidence.evidence_type, 50)
    confidence = evidence.confidence
    reputation = _reputation_from_evidence(evidence)
    quality = _quality_from_evidence(evidence)
    exposure = _exposure_from_evidence(evidence)

    params = RiskParameters(
        severity=severity,
        confidence=confidence,
        reputation=reputation,
        evidence_quality=quality,
        exposure=exposure,
    )
    return compute_risk(params)


def _reputation_from_evidence(evidence: Evidence) -> int:
    """Neutral unless module provided a reputation in provenance."""
    prov = evidence.provenance or {}
    value = prov.get("reputation")
    if isinstance(value, int) and 0 <= value <= 100:
        return value
    return _NEUTRAL_REPUTATION


def _quality_from_evidence(evidence: Evidence) -> int:
    """Provenance richness is a rough proxy for evidence quality."""
    prov = evidence.provenance or {}
    score = 30
    if evidence.raw_reference:
        score += 20
    if evidence.timestamp:
        score += 10
    if prov:
        score += min(40, len(prov) * 5)
    return min(100, score)


def _exposure_from_evidence(evidence: Evidence) -> int:
    """Exposure requires a hostname in provenance to be meaningful."""
    prov = evidence.provenance or {}
    if prov.get("hostname"):
        return 70
    return 30


# ---------- per-case ----------
def assess_case(evidence_list: list[Evidence]) -> RiskScore:
    """Assess a case: max over evidence, never average."""
    if not evidence_list:
        return RiskScore(
            score=0.0,
            classification="insufficient_data",
            breakdown={"evidence_count": 0.0},
            reasons=["No evidence in case"],
        )

    per_evidence = [assess_evidence(ev) for ev in evidence_list]
    strongest = max(per_evidence, key=lambda r: r.score)

    # Aggregate reasons from all evidence whose score is close to the max.
    reasons: list[str] = []
    for r in per_evidence:
        if r.score >= strongest.score - 10:
            for reason in r.reasons:
                if reason not in reasons:
                    reasons.append(reason)

    breakdown = dict(strongest.breakdown)
    breakdown["evidence_count"] = float(len(evidence_list))
    breakdown["max_evidence_score"] = strongest.score
    breakdown["mean_evidence_score"] = round(
        sum(r.score for r in per_evidence) / len(per_evidence), 2
    )

    return RiskScore(
        score=strongest.score,
        classification=strongest.classification,
        breakdown=breakdown,
        reasons=reasons,
    )
