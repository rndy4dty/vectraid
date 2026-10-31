"""PhishTrace authentication analysis - Phase 3c.

Interprets Authentication-Results headers into structured details and
findings.

Design rules:
  - Never invents data. If Authentication-Results is absent -> all 'unknown'.
  - Emits findings for explicit fails (spf/dkim/dmarc) and for domain
    mismatches (DKIM header.d != From domain).
  - No findings are emitted when there is no data (unknown != fail).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.modules.phishtrace.parser import EmailParseResult


@dataclass(frozen=True)
class AuthDetails:
    spf_result: str = "unknown"
    spf_domain: str | None = None
    dkim_result: str = "unknown"
    dkim_domain: str | None = None
    dmarc_result: str = "unknown"
    dmarc_domain: str | None = None


@dataclass(frozen=True)
class AuthenticationFinding:
    code: str
    severity: str  # info | low | medium | high
    detail: str


@dataclass(frozen=True)
class AuthAnalysisResult:
    details: AuthDetails
    findings: list[AuthenticationFinding] = field(default_factory=list)


_SPF_RE = re.compile(
    r"spf=(\w+)(?:\s+smtp\.mailfrom=([A-Za-z0-9._-]+))?", re.IGNORECASE
)
_DKIM_RE = re.compile(
    r"dkim=(\w+)(?:\s+header\.d=([A-Za-z0-9._-]+))?", re.IGNORECASE
)
_DMARC_RE = re.compile(
    r"dmarc=(\w+)(?:\s+header\.from=([A-Za-z0-9._-]+))?", re.IGNORECASE
)


def analyze_authentication(parsed: EmailParseResult) -> AuthAnalysisResult:
    """Extract details and emit findings for authentication results."""
    raw = parsed.raw_auth_header

    details = _parse_details(raw)
    findings = _compute_findings(details, parsed)
    return AuthAnalysisResult(details=details, findings=findings)


def _parse_details(raw: str | None) -> AuthDetails:
    if not raw:
        return AuthDetails()

    spf_m = _SPF_RE.search(raw)
    dkim_m = _DKIM_RE.search(raw)
    dmarc_m = _DMARC_RE.search(raw)

    return AuthDetails(
        spf_result=(spf_m.group(1).lower() if spf_m else "unknown"),
        spf_domain=(
            spf_m.group(2).lower() if spf_m and spf_m.group(2) else None
        ),
        dkim_result=(dkim_m.group(1).lower() if dkim_m else "unknown"),
        dkim_domain=(
            dkim_m.group(2).lower() if dkim_m and dkim_m.group(2) else None
        ),
        dmarc_result=(dmarc_m.group(1).lower() if dmarc_m else "unknown"),
        dmarc_domain=(
            dmarc_m.group(2).lower() if dmarc_m and dmarc_m.group(2) else None
        ),
    )


def _compute_findings(
    details: AuthDetails, parsed: EmailParseResult
) -> list[AuthenticationFinding]:
    findings: list[AuthenticationFinding] = []

    if details.spf_result == "fail":
        findings.append(
            AuthenticationFinding(
                code="spf_fail",
                severity="high",
                detail="SPF authentication failed",
            )
        )
    if details.dkim_result == "fail":
        findings.append(
            AuthenticationFinding(
                code="dkim_fail",
                severity="high",
                detail="DKIM authentication failed",
            )
        )
    if details.dmarc_result == "fail":
        findings.append(
            AuthenticationFinding(
                code="dmarc_fail",
                severity="high",
                detail="DMARC authentication failed",
            )
        )

    from_domain = (parsed.headers.from_domain or "").lower() or None
    if details.dkim_domain and from_domain and details.dkim_domain != from_domain:
        findings.append(
            AuthenticationFinding(
                code="dkim_domain_mismatch_from",
                severity="high",
                detail=(
                    f"DKIM header.d ({details.dkim_domain}) does not match "
                    f"From domain ({from_domain})"
                ),
            )
        )

    return findings
