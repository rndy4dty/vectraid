"""Base rule contract and data structures - Phase 5c."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.modules.huntscope.parser import NormalizedEvent


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: str  # info | low | medium | high
    mitre_technique: str
    description: str
    event: NormalizedEvent


@dataclass(frozen=True)
class HuntResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    event_count: int = 0
    finding_count: int = 0


class BaseRule(ABC):
    """Every detection rule inherits from this.

    Subclasses set:
      - rule_id: unique stable string
      - rule_name: human-readable
      - severity: info | low | medium | high
      - mitre_technique: ATT&CK ID (or "" if not applicable)
    And implement:
      - match(event) -> Finding | None
    """

    rule_id: str = "base"
    rule_name: str = "Base rule"
    severity: str = "info"
    mitre_technique: str = ""

    @abstractmethod
    def match(self, event: NormalizedEvent) -> Finding | None:
        ...
