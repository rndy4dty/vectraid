"""Phase 4c - MalTrace YARA scanning tests (test-first)."""
from pathlib import Path

from app.modules.maltrace.yara_scanner import (
    YaraMatch,
    YaraScanResult,
    compile_rules,
    scan_file,
)

_FIXTURES = (
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "malware"
)


# ---------- dataclass shapes ----------
def test_yara_match_fields():
    m = YaraMatch(
        rule_name="test_rule",
        tags=["test"],
        meta={"severity": "info"},
        strings_matched=["$a@0:10"],
    )
    assert m.rule_name == "test_rule"
    assert m.tags == ["test"]


def test_yara_scan_result_fields():
    r = YaraScanResult(
        matches=[],
        scanned_path="x",
        error=None,
        timed_out=False,
    )
    assert r.matches == []
    assert r.error is None
    assert r.timed_out is False


# ---------- compile_rules ----------
def test_compile_rules_from_default_dir():
    rules = compile_rules()
    assert rules is not None


# ---------- scan_file: positive match ----------
def test_scan_text_file_matches_benign_rule():
    rules = compile_rules()
    result = scan_file(str(_FIXTURES / "text.txt"), rules)
    assert result.error is None
    assert result.timed_out is False
    names = {m.rule_name for m in result.matches}
    assert "test_benign_marker" in names


# ---------- scan_file: negative match ----------
def test_scan_pe_file_does_not_match_benign_rule():
    rules = compile_rules()
    result = scan_file(str(_FIXTURES / "sample_pe_minimal.exe"), rules)
    assert result.error is None
    names = {m.rule_name for m in result.matches}
    assert "test_benign_marker" not in names


# ---------- scan_file: no suspicious matches in clean fixtures ----------
def test_scan_text_file_no_suspicious_matches():
    rules = compile_rules()
    result = scan_file(str(_FIXTURES / "text.txt"), rules)
    suspicious = {m.rule_name for m in result.matches
                  if m.rule_name.startswith("suspicious_")}
    assert suspicious == set()


# ---------- scan_file: metadata carried through ----------
def test_scan_text_file_carries_meta():
    rules = compile_rules()
    result = scan_file(str(_FIXTURES / "text.txt"), rules)
    match = next(m for m in result.matches if m.rule_name == "test_benign_marker")
    assert match.meta.get("severity") == "info"
    assert match.meta.get("author") == "VECTRAID test suite"


# ---------- scan_file: missing file ----------
def test_scan_missing_file_raises():
    import pytest

    rules = compile_rules()
    with pytest.raises(FileNotFoundError):
        scan_file("/nonexistent/path/file.bin", rules)


# ---------- compile_rules: bad rules dir (fail-soft) ----------
def test_compile_rules_bad_dir_raises_or_returns_error():
    """A nonexistent rules dir should not silently succeed."""
    import pytest

    with pytest.raises(Exception):
        compile_rules("/nonexistent/rules/dir")
