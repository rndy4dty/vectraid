"""Risk assessment engine — Phase 7."""
from dataclasses import dataclass

WEIGHTS = {
    "severity": 0.30,
    "confidence": 0.25,
    "reputation": 0.20,
    "evidence_quality": 0.15,
    "exposure": 0.10,
}


@dataclass
class RiskScore:
    score: float
    classification: str
    breakdown: dict[str, float]


def compute_risk(
    severity: float,
    confidence: float,
    reputation: float,
    evidence_quality: float,
    exposure: float,
) -> RiskScore:
    raise NotImplementedError("Phase 7 — to be implemented")
