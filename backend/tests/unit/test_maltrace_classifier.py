"""Phase 4d - MalTrace classification tests (test-first).

Classifier is pure: takes the outputs of identify_file, extract_metadata,
and scan_file, and returns a verdict. No I/O in the classifier itself.
"""
from app.modules.maltrace.classifier import (
    ClassificationResult,
    classify_file,
)
from app.modules.maltrace.identifier import FileIdentification
from app.modules.maltrace.metadata import FileMetadata, PEInfo
from app.modules.maltrace.yara_scanner import YaraMatch, YaraScanResult


def _id(magic: str = "pe", ext: str = "exe", mismatch: bool = False) -> FileIdentification:
    return FileIdentification(
        magic=magic,
        mime="application/x-dosexec",
        extension=ext,
        extension_mismatch=mismatch,
        size=1024,
        path="x",
    )


def _meta(pe: PEInfo | None = None, strings: list[str] | None = None) -> FileMetadata:
    return FileMetadata(
        path="x",
        size=1024,
        md5="a" * 32,
        sha1="b" * 40,
        sha256="c" * 64,
        pe_info=pe,
        strings_sample=strings or [],
        strings_truncated=False,
        error=None,
    )


def _yara(*names_severity: tuple[str, str]) -> YaraScanResult:
    matches = [
        YaraMatch(rule_name=n, tags=[], meta={"severity": s}, strings_matched=[])
        for n, s in names_severity
    ]
    return YaraScanResult(matches=matches, scanned_path="x", error=None, timed_out=False)


def _no_yara() -> YaraScanResult:
    return YaraScanResult(matches=[], scanned_path="x", error=None, timed_out=False)


def _pe_with_imports(*dlls: str) -> PEInfo:
    return PEInfo(
        machine="x86",
        subsystem="CLI",
        timestamp=0,
        entry_point=0x1000,
        section_count=3,
        imported_dlls=list(dlls),
    )


# ---------- dataclass shape ----------
def test_result_fields():
    r = ClassificationResult(
        classification="clean",
        confidence=0,
        reasons=["test"],
        evidence={},
    )
    assert r.classification == "clean"
    assert r.confidence == 0
    assert r.reasons == ["test"]


# ---------- YARA-only signals ----------
def test_yara_high_alone_is_suspicious_or_malicious():
    result = classify_file(_id(), _meta(), _yara(("evil_rule", "high")))
    assert result.classification in {"suspicious", "malicious"}
    assert any("evil_rule" in r for r in result.reasons)


def test_yara_info_alone_is_not_malicious():
    result = classify_file(_id(), _meta(), _yara(("marker", "info")))
    assert result.classification != "malicious"


def test_yara_medium_plus_high_is_malicious():
    result = classify_file(
        _id(),
        _meta(),
        _yara(("r1", "high"), ("r2", "medium")),
    )
    assert result.classification == "malicious"


# ---------- Extension mismatch ----------
def test_extension_mismatch_contributes():
    result = classify_file(_id(mismatch=True), _meta(), _no_yara())
    assert result.confidence > 0
    assert any("extension" in r.lower() for r in result.reasons)


# ---------- PE imports ----------
def test_injection_imports_contribute():
    pe = _pe_with_imports("CreateRemoteThread", "VirtualAllocEx")
    result = classify_file(_id(), _meta(pe=pe), _no_yara())
    assert result.confidence > 0
    assert any("CreateRemoteThread" in r or "VirtualAllocEx" in r for r in result.reasons)


def test_exec_imports_contribute():
    pe = _pe_with_imports("WinExec")
    result = classify_file(_id(), _meta(pe=pe), _no_yara())
    assert result.confidence > 0


# ---------- Strings ----------
def test_strings_with_powershell_enc_contribute():
    result = classify_file(
        _id(),
        _meta(strings=["powershell -enc ABCDEF"]),
        _no_yara(),
    )
    assert result.confidence > 0
    assert any("powershell" in r.lower() for r in result.reasons)


def test_strings_with_url_contribute():
    result = classify_file(
        _id(),
        _meta(strings=["http://evil.test/path"]),
        _no_yara(),
    )
    assert result.confidence > 0


# ---------- no evidence ----------
def test_no_evidence_no_pe_is_unknown():
    """A .txt file with no PE, no YARA, no strings -> unknown, not clean."""
    result = classify_file(
        FileIdentification(
            magic="unknown",
            mime="application/octet-stream",
            extension="bin",
            extension_mismatch=False,
            size=100,
            path="x",
        ),
        _meta(pe=None, strings=[]),
        _no_yara(),
    )
    assert result.classification == "unknown"


def test_clean_pe_with_no_signals_is_clean():
    """A valid PE with no imports, no YARA, no suspicious strings -> clean."""
    pe = PEInfo(
        machine="x86",
        subsystem="GUI",
        timestamp=0,
        entry_point=0x1000,
        section_count=1,
        imported_dlls=[],
    )
    result = classify_file(_id(), _meta(pe=pe), _no_yara())
    assert result.classification == "clean"


# ---------- evidence snapshot ----------
def test_evidence_is_populated():
    result = classify_file(_id(mismatch=True), _meta(), _yara(("r1", "high")))
    assert "identification" in result.evidence
    assert "metadata" in result.evidence
    assert "yara" in result.evidence


# ---------- reasons are human-readable ----------
def test_reasons_are_strings():
    result = classify_file(_id(mismatch=True), _meta(), _yara(("r1", "high")))
    for r in result.reasons:
        assert isinstance(r, str)
        assert len(r) > 0
