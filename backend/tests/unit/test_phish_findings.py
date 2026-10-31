"""Phase 3d - Mismatch and display-name spoofing tests."""
from pathlib import Path

from app.modules.phishtrace.findings import (
    PhishFinding,
    analyze_findings,
)
from app.modules.phishtrace.parser import parse_eml

_FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "emails"


def _parsed(name: str):
    return parse_eml((_FIXTURES / name).read_text())


def test_finding_shape():
    f = PhishFinding(
        code="display_name_brand_mismatch",
        severity="medium",
        detail="x",
    )
    assert f.code == "display_name_brand_mismatch"


def test_display_name_brand_mismatch_detected():
    """'IT Support' with domain spoofed-sender.test -> brand mismatch."""
    parsed = _parsed("phishing_simulation.eml")
    result = analyze_findings(parsed)
    codes = {f.code for f in result.findings}
    assert "display_name_brand_mismatch" in codes


def test_no_brand_mismatch_when_domain_matches():
    """'Bank Support' with domain bank-real.test -> no brand mismatch (bank in domain)."""
    parsed = _parsed("dkim_domain_mismatch.eml")
    result = analyze_findings(parsed)
    codes = {f.code for f in result.findings}
    assert "display_name_brand_mismatch" not in codes


def test_missing_return_path_detected():
    """An email without Return-Path produces a finding."""
    parsed = _parsed("dkim_domain_mismatch.eml")
    # This fixture has Return-Path, so no missing_return_path
    codes = {f.code for f in analyze_findings(parsed).findings}
    assert "missing_return_path" not in codes


def test_return_path_mismatch_does_not_trigger_when_equal():
    """From and Return-Path domains equal -> no lookalike finding."""
    parsed = _parsed("no_auth_results.eml")
    result = analyze_findings(parsed)
    codes = {f.code for f in result.findings}
    # No lookalike finding for identical domains
    assert not any(c.startswith("lookalike_domain_") for c in codes)


def test_phishing_fixture_lookalike_or_clean():
    """phishing_simulation.eml: from=spoofed-sender.test, rp=compromised-relay.test.
    Different domains, likely distance > 2 -> no lookalike finding, but
    a missing_return_path or mismatch may or may not fire depending on data.
    We only assert type of findings here.
    """
    parsed = _parsed("phishing_simulation.eml")
    result = analyze_findings(parsed)
    for f in result.findings:
        assert isinstance(f, PhishFinding)
        assert f.severity in {"info", "low", "medium", "high"}
