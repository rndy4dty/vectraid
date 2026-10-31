"""HuntScope detection rules package - Phase 5c."""
from app.modules.huntscope.rules.auth import (
    ExplicitCredentialRule,
    FailedLogonRule,
)
from app.modules.huntscope.rules.base import BaseRule, Finding, HuntResult
from app.modules.huntscope.rules.network import NonStandardPortRule
from app.modules.huntscope.rules.process import (
    EncodedPowerShellRule,
    Rundll32UserWritableRule,
)


def default_rules() -> list[BaseRule]:
    """Return a fresh list of default rule instances."""
    return [
        EncodedPowerShellRule(),
        Rundll32UserWritableRule(),
        NonStandardPortRule(),
        FailedLogonRule(),
        ExplicitCredentialRule(),
    ]


def hunt(events, rules: list[BaseRule] | None = None) -> HuntResult:
    """Run rules against events. Fail-soft: broken rule -> error, others run."""
    rule_list = rules if rules is not None else default_rules()
    findings: list[Finding] = []
    errors: list[str] = []

    for event in events:
        for rule in rule_list:
            try:
                finding = rule.match(event)
            except Exception as exc:  # noqa: BLE001 - fail-soft boundary
                errors.append(
                    f"rule {rule.rule_id} raised {type(exc).__name__}: {exc}"
                )
                continue
            if finding is not None:
                findings.append(finding)

    return HuntResult(
        findings=findings,
        errors=errors,
        event_count=len(events),
        finding_count=len(findings),
    )


__all__ = [
    "BaseRule",
    "Finding",
    "HuntResult",
    "ExplicitCredentialRule",
    "FailedLogonRule",
    "NonStandardPortRule",
    "EncodedPowerShellRule",
    "Rundll32UserWritableRule",
    "default_rules",
    "hunt",
]
