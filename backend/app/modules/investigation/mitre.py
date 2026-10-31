"""MITRE ATT&CK mapping - Phase 7d.

Maps evidence to ATT&CK techniques using explicit tables, not keyword
matching. Every mapping carries a rationale and inherits confidence from
the source evidence.

Design rules:
  - Mapping tables are data, not if/else chains.
  - No technique is claimed without an explicit indicator in provenance.
  - Failures (like dmarc_fail) are not techniques; they are states.
  - Version is recorded so mappings can be audited against ATT&CK releases.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.modules.investigation.evidence import Evidence

# ATT&CK version this mapping table was authored against.
# Update deliberately when the table is reviewed against a newer release.
ATTACK_VERSION = "v14"


@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str
    technique_name: str
    tactic: str


@dataclass(frozen=True)
class AttackMapping:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: int
    evidence_reference: str
    rationale: str = field(default="")


# ---------- reference table ----------
_TECHNIQUES: dict[str, AttackTechnique] = {
    "T1059.001": AttackTechnique(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
    ),
    "T1218.011": AttackTechnique(
        technique_id="T1218.011",
        technique_name="Rundll32",
        tactic="Defense Evasion",
    ),
    "T1110": AttackTechnique(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
    ),
    "T1071": AttackTechnique(
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        tactic="Command and Control",
    ),
    "T1566.002": AttackTechnique(
        technique_id="T1566.002",
        technique_name="Spearphishing Link",
        tactic="Initial Access",
    ),
    "T1204.002": AttackTechnique(
        technique_id="T1204.002",
        technique_name="Malicious File",
        tactic="Execution",
    ),
}

# ---------- rule_id -> technique ----------
_HUNT_RULE_TO_TECHNIQUE: dict[str, str] = {
    "process_powershell_encoded": "T1059.001",
    "process_rundll32_user_writable": "T1218.011",
    "auth_failed_logon": "T1110",
    "network_non_standard_port": "T1071",
}

# ---------- phishtrace finding_code -> technique ----------
_PHISH_FINDING_TO_TECHNIQUE: dict[str, str] = {
    "display_name_brand_mismatch": "T1566.002",
    "lookalike_domain_return_path": "T1566.002",
    "lookalike_domain_reply_to": "T1566.002",
}

# ---------- maltrace verdict -> technique ----------
_MALWARE_VERDICT_TO_TECHNIQUE: dict[str, str] = {
    "malicious": "T1204.002",
}

# ---------- rationale templates ----------
_RATIONALES: dict[str, str] = {
    "T1059.001": "Encoded PowerShell invocation detected by HuntScope rule",
    "T1218.011": "Rundll32 executed from user-writable path (proxy execution)",
    "T1110": "Repeated failed logon attempt detected",
    "T1071": "Outbound connection to non-standard port (possible C2 channel)",
    "T1566.002": "Phishing indicators: brand mismatch or lookalike domain",
    "T1204.002": "Malicious file verdict from static analysis",
}


# ---------- public API ----------
def map_evidence(evidence: Evidence) -> list[AttackMapping]:
    """Return ATT&CK mappings justified by this evidence."""
    prov = evidence.provenance or {}
    mappings: list[AttackMapping] = []

    # HuntScope rule_id
    rule_id = prov.get("rule_id")
    if isinstance(rule_id, str):
        tech_id = _HUNT_RULE_TO_TECHNIQUE.get(rule_id)
        if tech_id:
            m = _build(tech_id, evidence)
            if m is not None:
                mappings.append(m)

    # PhishTrace finding_code
    finding_code = prov.get("finding_code")
    if isinstance(finding_code, str):
        tech_id = _PHISH_FINDING_TO_TECHNIQUE.get(finding_code)
        if tech_id:
            m = _build(tech_id, evidence)
            if m is not None:
                mappings.append(m)

    # MalTrace verdict
    verdict = prov.get("verdict")
    if isinstance(verdict, str):
        tech_id = _MALWARE_VERDICT_TO_TECHNIQUE.get(verdict)
        if tech_id:
            m = _build(tech_id, evidence)
            if m is not None:
                mappings.append(m)

    return mappings


def map_case(evidence_list: list[Evidence]) -> list[AttackMapping]:
    """Aggregate and deduplicate ATT&CK mappings across a case."""
    if not evidence_list:
        return []

    seen: set[tuple[str, str]] = set()
    out: list[AttackMapping] = []

    for ev in evidence_list:
        for mapping in map_evidence(ev):
            key = (mapping.technique_id, mapping.evidence_reference)
            if key in seen:
                continue
            seen.add(key)
            out.append(mapping)

    return out


# ---------- internal ----------
def _build(tech_id: str, evidence: Evidence) -> AttackMapping | None:
    tech = _TECHNIQUES.get(tech_id)
    if tech is None:
        return None

    # Confidence tracks the evidence's confidence; a rule match on
    # low-confidence evidence should not assert the technique strongly.
    confidence = max(0, min(100, evidence.confidence))

    rationale = _RATIONALES.get(tech_id, "Technique mapped from evidence")

    return AttackMapping(
        technique_id=tech.technique_id,
        technique_name=tech.technique_name,
        tactic=tech.tactic,
        confidence=confidence,
        evidence_reference=evidence.evidence_id,
        rationale=rationale,
    )
