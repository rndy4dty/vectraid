"""Network-related detection rules - Phase 5c."""
from __future__ import annotations

from app.modules.huntscope.parser import NormalizedEvent
from app.modules.huntscope.rules.base import BaseRule, Finding


class NonStandardPortRule(BaseRule):
    rule_id = "network_non_standard_port"
    rule_name = "Outbound connection to non-standard port"
    severity = "medium"
    mitre_technique = "T1071"

    _STANDARD_PORTS = frozenset({20, 21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995})

    def match(self, event: NormalizedEvent) -> Finding | None:
        if event.event_type != "network":
            return None
        port = event.dst_port
        if port is None:
            return None
        if port in self._STANDARD_PORTS:
            return None
        # Ignore very high ephemeral port ranges used for return traffic.
        if 49152 <= port <= 65535:
            return None
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            mitre_technique=self.mitre_technique,
            description=f"Outbound connection to non-standard port {port}",
            event=event,
        )
