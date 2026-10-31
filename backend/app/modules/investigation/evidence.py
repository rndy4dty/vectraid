"""Investigation evidence management - Phase 7a.

Evidence is the atomic unit of investigation. Every finding that enters
a case is stored as Evidence with full provenance.

Design rules:
  - Raw reference is mandatory: without it, evidence cannot be verified.
  - Timestamp is mandatory: without it, evidence cannot enter the timeline.
  - Confidence is 0-100 and validated.
  - Three information levels are kept distinct at the type level:
      raw_reference  -> points to raw data (email, file, log line)
      finding        -> analytical result (what the module concluded)
      (analyst_conclusion is NOT modeled here; that lives in Case Management)
  - The store is in-memory for Phase 7; persistence arrives in Phase 8.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class EvidenceType(StrEnum):
    EMAIL_ANALYSIS = "email_analysis"
    FILE_ANALYSIS = "file_analysis"
    HUNT_FINDING = "hunt_finding"
    IOC_MATCH = "ioc_match"
    THREAT_INTEL = "threat_intel"


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    case_id: str
    source_module: str
    evidence_type: EvidenceType
    raw_reference: str
    finding: str
    timestamp: str
    confidence: int
    provenance: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.raw_reference:
            raise ValueError("raw_reference is required")
        if not self.timestamp:
            raise ValueError("timestamp is required")
        if not isinstance(self.confidence, int) or isinstance(self.confidence, bool):
            raise ValueError("confidence must be an int")
        if not (0 <= self.confidence <= 100):
            raise ValueError(
                f"confidence must be 0..100, got {self.confidence}"
            )


class EvidenceStore:
    """In-memory evidence store. Append-only, keyed by evidence_id."""

    def __init__(self) -> None:
        self._items: dict[str, Evidence] = {}

    # ---------- write ----------
    def add(self, evidence: Evidence) -> None:
        if evidence.evidence_id in self._items:
            raise ValueError(
                f"evidence already exists: {evidence.evidence_id}"
            )
        self._items[evidence.evidence_id] = evidence

    def remove(self, evidence_id: str) -> None:
        self._items.pop(evidence_id, None)

    # ---------- read ----------
    def get(self, evidence_id: str) -> Evidence | None:
        return self._items.get(evidence_id)

    def count(self) -> int:
        return len(self._items)

    def list_by_case(self, case_id: str) -> list[Evidence]:
        return [e for e in self._items.values() if e.case_id == case_id]

    def list_by_module(self, module: str) -> list[Evidence]:
        return [e for e in self._items.values() if e.source_module == module]

    def list_all(self) -> list[Evidence]:
        return list(self._items.values())
