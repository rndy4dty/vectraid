"""Process-related detection rules - Phase 5c."""
from __future__ import annotations

from app.modules.huntscope.parser import NormalizedEvent
from app.modules.huntscope.rules.base import BaseRule, Finding


class EncodedPowerShellRule(BaseRule):
    rule_id = "process_powershell_encoded"
    rule_name = "Encoded PowerShell command"
    severity = "high"
    mitre_technique = "T1059.001"

    _MARKERS = ("-enc ", "-enc\t", "-encodedcommand", " -e ")

    def match(self, event: NormalizedEvent) -> Finding | None:
        if event.event_type != "process":
            return None
        cmd = (event.command_line or "").lower()
        proc = (event.process or "").lower()
        if "powershell" not in proc and "powershell" not in cmd:
            return None
        if not any(m in cmd for m in self._MARKERS):
            return None
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            mitre_technique=self.mitre_technique,
            description="PowerShell launched with an encoded command payload",
            event=event,
        )


class Rundll32UserWritableRule(BaseRule):
    rule_id = "process_rundll32_user_writable"
    rule_name = "Rundll32 executing from user-writable path"
    severity = "high"
    mitre_technique = "T1218.011"

    _SUSPICIOUS_PATHS = (
        "c:\\users\\public\\",
        "c:\\windows\\temp\\",
        "%temp%",
        "\\appdata\\local\\temp\\",
    )

    def match(self, event: NormalizedEvent) -> Finding | None:
        if event.event_type != "process":
            return None
        cmd = (event.command_line or "").lower()
        proc = (event.process or "").lower()
        if "rundll32" not in proc and "rundll32" not in cmd:
            return None
        if not any(p in cmd for p in self._SUSPICIOUS_PATHS):
            return None
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            mitre_technique=self.mitre_technique,
            description=(
                "Rundll32 invoked a DLL from a user-writable directory "
                "(defense evasion / proxy execution)"
            ),
            event=event,
        )
