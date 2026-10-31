"""Phase 3c - Authentication analysis tests (test-first)."""
from pathlib import Path

from app.modules.phishtrace.auth import (
    AuthDetails,
    AuthenticationFinding,
    analyze_authentication,
)
from app.modules.phishtrace.parser import parse_eml

_FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "emails"


def _parsed(name: str):
    return parse_eml((_FIXTURES / name).read_text())


# ---------- AuthDetails shape ----------
def test_auth_details_fields():
    d = AuthDetails(
        spf_result="pass",
        spf_domain="example.test",
        dkim_result="fail",
        dkim_domain="compromised.test",
        dmarc_result="fail",
        dmarc_domain="example.test",
    )
    assert d.spf_result == "pass"
    assert d.spf_domain == "example.test"
    assert d.dkim_result == "fail"
    assert d.dmarc_result == "fail"


# ---------- phishing_simulation.eml ----------
def test_phishing_simulation_details():
    parsed = _parsed("phishing_simulation.eml")
    details = analyze_authentication(parsed).details
    assert details.spf_result == "fail"
    assert details.spf_domain == "spoofed-sender.test"
    assert details.dkim_result == "fail"
    assert details.dkim_domain == "spoofed-sender.test"
    assert details.dmarc_result == "fail"
    assert details.dmarc_domain == "spoofed-sender.test"


# ---------- dkim_domain_mismatch.eml ----------
def test_dkim_domain_mismatch_details():
    parsed = _parsed("dkim_domain_mismatch.eml")
    result = analyze_authentication(parsed)
    d = result.details
    assert d.spf_result == "pass"
    assert d.spf_domain == "bank-real.test"
    assert d.dkim_result == "fail"
    assert d.dkim_domain == "compromised-relay.test"
    assert d.dmarc_result == "fail"
    assert d.dmarc_domain == "bank-real.test"

    # Expect a finding for DKIM domain != From domain
    codes = {f.code for f in result.findings}
    assert "dkim_domain_mismatch_from" in codes


# ---------- no_auth_results.eml ----------
def test_no_auth_results_returns_unknown():
    parsed = _parsed("no_auth_results.eml")
    result = analyze_authentication(parsed)
    d = result.details
    assert d.spf_result == "unknown"
    assert d.dkim_result == "unknown"
    assert d.dmarc_result == "unknown"
    assert d.spf_domain is None
    assert d.dkim_domain is None
    assert d.dmarc_domain is None

    # No findings when there is no data
    assert result.findings == []


# ---------- findings shape ----------
def test_finding_has_expected_fields():
    f = AuthenticationFinding(
        code="dkim_domain_mismatch_from",
        severity="high",
        detail="DKIM header.d does not match From domain",
    )
    assert f.code == "dkim_domain_mismatch_from"
    assert f.severity == "high"
    assert f.detail


# ---------- pass scenario: no mismatch findings ----------
def test_pass_scenario_has_no_mismatch_findings():
    parsed = _parsed("phishing_simulation.eml")
    result = analyze_authentication(parsed)
    # This fixture has dkim.fail, dmarc.fail -> those are findings
    # but NO dkim_domain_mismatch_from (dkim domain == from domain)
    codes = {f.code for f in result.findings}
    assert "dkim_domain_mismatch_from" not in codes


# ---------- failure findings emitted for fails ----------
def test_failure_results_become_findings():
    parsed = _parsed("phishing_simulation.eml")
    result = analyze_authentication(parsed)
    codes = {f.code for f in result.findings}
    assert "spf_fail" in codes
    assert "dkim_fail" in codes
    assert "dmarc_fail" in codes
