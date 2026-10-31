"""PhishTrace header/finding analysis - Phase 3d.

Detects display-name spoofing, lookalike domains, and structural header
anomalies. Emits structured PhishFinding objects.

Design rules:
  - No external calls, no DNS. Pure header analysis.
  - Findings are evidence-based: each code maps to a verifiable fact.
  - Never assert brand impersonation beyond what the display name literally
    contains vs the domain. Heuristics, not verdicts.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.modules.phishtrace.parser import EmailParseResult

# Words commonly used in brand impersonation display names.
_BRAND_WORDS = frozenset(
    {
        "support", "it", "security", "admin", "billing", "helpdesk",
        "bank", "payroll", "hr", "account", "verify", "notification",
    }
)

_DISPLAY_NAME_RE = re.compile(r'^\s*"?([^"<]+?)"?\s*<')


@dataclass(frozen=True)
class PhishFinding:
    code: str
    severity: str  # info | low | medium | high
    detail: str


@dataclass(frozen=True)
class PhishFindingsResult:
    findings: list[PhishFinding] = field(default_factory=list)


def analyze_findings(parsed: EmailParseResult) -> PhishFindingsResult:
    """Run all mismatch/spoofing heuristics on parsed email."""
    findings: list[PhishFinding] = []

    _check_display_name_spoof(parsed, findings)
    _check_lookalike_domains(parsed, findings)
    _check_empty_return_path(parsed, findings)

    return PhishFindingsResult(findings=findings)


# ---------- checks ----------
def _extract_display_name(from_value: str) -> str | None:
    if not from_value:
        return None
    m = _DISPLAY_NAME_RE.match(from_value)
    if m:
        return m.group(1).strip()
    return None


def _check_display_name_spoof(
    parsed: EmailParseResult, findings: list[PhishFinding]
) -> None:
    display = _extract_display_name(parsed.headers.from_)
    if not display:
        return
    domain = (parsed.headers.from_domain or "").lower()
    if not domain:
        return

    tokens = {t.lower() for t in re.findall(r"[A-Za-z]+", display)}
    brand_hits = tokens & _BRAND_WORDS
    if not brand_hits:
        return

    # If any brand word appears literally in the domain, it's probably legit.
    if any(word in domain for word in brand_hits):
        return

    findings.append(
        PhishFinding(
            code="display_name_brand_mismatch",
            severity="medium",
            detail=(
                f"Display name '{display}' contains brand-like term(s) "
                f"{sorted(brand_hits)} not present in From domain '{domain}'"
            ),
        )
    )


def _levenshtein(a: str, b: str) -> int:
    """Iterative Levenshtein distance. O(len(a)*len(b))."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(
                min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            )
        prev = curr
    return prev[-1]


def _check_lookalike_domains(
    parsed: EmailParseResult, findings: list[PhishFinding]
) -> None:
    from_d = (parsed.headers.from_domain or "").lower() or None
    rp_d = (parsed.headers.return_path_domain or "").lower() or None
    reply_d = (parsed.headers.reply_to_domain or "").lower() or None

    for label, other in (("return_path", rp_d), ("reply_to", reply_d)):
        if not from_d or not other or from_d == other:
            continue
        distance = _levenshtein(from_d, other)
        # Distance 1-2 with same length class -> likely lookalike
        if 1 <= distance <= 2 and abs(len(from_d) - len(other)) <= 2:
            findings.append(
                PhishFinding(
                    code=f"lookalike_domain_{label}",
                    severity="medium",
                    detail=(
                        f"From domain '{from_d}' is close to {label} domain "
                        f"'{other}' (Levenshtein={distance})"
                    ),
                )
            )


def _check_empty_return_path(
    parsed: EmailParseResult, findings: list[PhishFinding]
) -> None:
    if parsed.headers.return_path is None:
        findings.append(
            PhishFinding(
                code="missing_return_path",
                severity="low",
                detail="Return-Path header is absent or empty",
            )
        )
