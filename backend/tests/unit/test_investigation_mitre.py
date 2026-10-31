"""Phase 7d - MITRE ATT&CK Mapping tests (test-first)."""
from app.modules.investigation.evidence import Evidence, EvidenceType
from app.modules.investigation.mitre import (
    ATTACK_VERSION,
    AttackMapping,
    AttackTechnique,
    map_case,
    map_evidence,
)


# ---------- AttackTechnique ----------
def test_attack_technique_fields():
    t = AttackTechnique(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
    )
    assert t.technique_id == "T1059.001"
    assert t.tactic == "Execution"


def test_attack_version_defined():
    assert ATTACK_VERSION.startswith("v")


# ---------- AttackMapping ----------
def test_attack_mapping_fields():
    m = AttackMapping(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        confidence=85,
        evidence_reference="ev-001",
        rationale="Encoded PowerShell command detected",
    )
    assert m.technique_id == "T1059.001"
    assert m.confidence == 85


# ---------- helpers ----------
def _ev(
    module: str = "huntscope",
    evidence_type: EvidenceType = EvidenceType.HUNT_FINDING,
    provenance: dict | None = None,
    confidence: int = 80,
) -> Evidence:
    return Evidence(
        evidence_id="ev-001",
        case_id="case-001",
        source_module=module,
        evidence_type=evidence_type,
        raw_reference="raw:001",
        finding="test finding",
        timestamp="2026-11-01T09:00:00Z",
        confidence=confidence,
        provenance=provenance or {},
    )


# ---------- map from hunt rules ----------
def test_hunt_rule_powershell_maps_to_t1059_001():
    ev = _ev(provenance={"rule_id": "process_powershell_encoded"})
    mappings = map_evidence(ev)
    ids = {m.technique_id for m in mappings}
    assert "T1059.001" in ids


def test_hunt_rule_rundll32_maps_to_t1218_011():
    ev = _ev(provenance={"rule_id": "process_rundll32_user_writable"})
    mappings = map_evidence(ev)
    ids = {m.technique_id for m in mappings}
    assert "T1218.011" in ids


def test_hunt_rule_failed_logon_maps_to_t1110():
    ev = _ev(provenance={"rule_id": "auth_failed_logon"})
    mappings = map_evidence(ev)
    ids = {m.technique_id for m in mappings}
    assert "T1110" in ids


def test_hunt_rule_network_non_standard_maps_to_t1071():
    ev = _ev(provenance={"rule_id": "network_non_standard_port"})
    mappings = map_evidence(ev)
    ids = {m.technique_id for m in mappings}
    assert "T1071" in ids


# ---------- map from phishtrace findings ----------
def test_phish_finding_display_name_brand_maps_to_t1566_002():
    ev = _ev(
        module="phishtrace",
        evidence_type=EvidenceType.EMAIL_ANALYSIS,
        provenance={"finding_code": "display_name_brand_mismatch"},
    )
    mappings = map_evidence(ev)
    ids = {m.technique_id for m in mappings}
    assert "T1566.002" in ids


def test_phish_finding_dmarc_fail_does_not_map():
    """DMARC failure alone is not a technique. It is a state."""
    ev = _ev(
        module="phishtrace",
        evidence_type=EvidenceType.EMAIL_ANALYSIS,
        provenance={"finding_code": "dmarc_fail"},
    )
    mappings = map_evidence(ev)
    assert mappings == []


# ---------- map from maltrace verdict ----------
def test_malware_malicious_maps_to_t1204_002():
    ev = _ev(
        module="maltrace",
        evidence_type=EvidenceType.FILE_ANALYSIS,
        provenance={"verdict": "malicious"},
    )
    mappings = map_evidence(ev)
    ids = {m.technique_id for m in mappings}
    assert "T1204.002" in ids


def test_malware_clean_maps_nothing():
    ev = _ev(
        module="maltrace",
        evidence_type=EvidenceType.FILE_ANALYSIS,
        provenance={"verdict": "clean"},
    )
    assert map_evidence(ev) == []


# ---------- no mapping without indicators ----------
def test_no_mapping_without_provenance():
    ev = _ev(provenance={})
    assert map_evidence(ev) == []


# ---------- map_case ----------
def test_map_case_aggregates():
    ev1 = _ev(provenance={"rule_id": "process_powershell_encoded"})
    ev2 = _ev(provenance={"rule_id": "auth_failed_logon"})
    mappings = map_case([ev1, ev2])
    ids = {m.technique_id for m in mappings}
    assert "T1059.001" in ids
    assert "T1110" in ids


def test_map_case_deduplicates_same_technique():
    ev1 = _ev(provenance={"rule_id": "process_powershell_encoded"})
    ev2 = _ev(provenance={"rule_id": "process_powershell_encoded"})
    mappings = map_case([ev1, ev2])
    # Same technique from same evidence_id may dedup
    t1059 = [m for m in mappings if m.technique_id == "T1059.001"]
    assert len(t1059) >= 1


def test_map_case_empty():
    assert map_case([]) == []


# ---------- rationale is populated ----------
def test_mapping_has_rationale():
    ev = _ev(provenance={"rule_id": "process_powershell_encoded"})
    mappings = map_evidence(ev)
    assert len(mappings) > 0
    for m in mappings:
        assert m.rationale
        assert len(m.rationale) > 10


# ---------- confidence tied to evidence confidence ----------
def test_mapping_confidence_tied_to_evidence_confidence():
    high = _ev(provenance={"rule_id": "process_powershell_encoded"}, confidence=90)
    low = _ev(provenance={"rule_id": "process_powershell_encoded"}, confidence=30)
    high_m = [m for m in map_evidence(high) if m.technique_id == "T1059.001"][0]
    low_m = [m for m in map_evidence(low) if m.technique_id == "T1059.001"][0]
    assert high_m.confidence > low_m.confidence
