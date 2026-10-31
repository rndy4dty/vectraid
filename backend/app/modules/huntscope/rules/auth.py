"""Authentication-related detection rules - Phase 5c."""
from __future__ import annotations

from app.modules.huntscope.parser import NormalizedEvent
from app.modules.huntscope.rules.base import BaseRule, Finding


class FailedLogonRule(BaseRule):
    rule_id = "auth_failed_logon"
    rule_name = "Failed logon"
    severity = "medium"
    mitre_technique = "T1110"

    def match(self, event: NormalizedEvent) -> Finding | None:
        if event.event_type != "auth":
            return None
        if event.event_id != 4625:
            return None
        user = event.user or "unknown"
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            mitre_technique=self.mitre_technique,
            description=f"Failed logon for user '{user}'",
            event=event,
        )


class ExplicitCredentialRule(BaseRule):
    rule_id = "auth_explicit_cred"
    rule_name = "Explicit credential use / special privileges assigned"
    severity = "info"
    mitre_technique = "T1078"

    def match(self, event: NormalizedEvent) -> Finding | None:
        if event.event_type != "auth":
            return None
        if event.event_id != 4672:
            return None
        user = event.user or "unknown"
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            mitre_technique=self.mitre_technique,
            description=f"Special privileges assigned to '{user}'",
            event=event,
        )
