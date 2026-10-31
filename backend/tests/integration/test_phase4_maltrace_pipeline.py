"""Phase 4 integration - end-to-end MalTrace pipeline."""
from pathlib import Path

from app.engine.hashing.hasher import hash_file
from app.modules.maltrace.classifier import classify_file
from app.modules.maltrace.identifier import identify_file
from app.modules.maltrace.metadata import extract_metadata
from app.modules.maltrace.yara_scanner import compile_rules, scan_file

_FIXTURES = (
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "malware"
)


def _run_pipeline(path: str):
    rules = compile_rules()
    ident = identify_file(path)
    meta = extract_metadata(path)
    yara = scan_file(path, rules)
    verdict = classify_file(ident, meta, yara)
    return ident, meta, yara, verdict


def test_pipeline_pe_minimal_is_clean():
    ident, meta, yara, verdict = _run_pipeline(
        str(_FIXTURES / "sample_pe_minimal.exe")
    )
    assert ident.magic == "pe"
    assert meta.pe_info is not None
    assert yara.error is None
    assert verdict.classification == "clean"
    assert verdict.confidence < 10


def test_pipeline_text_with_benign_marker_is_not_malicious():
    ident, _meta, yara, verdict = _run_pipeline(str(_FIXTURES / "text.txt"))
    assert ident.magic in {"text", "unknown"}
    yara_rules = {m.rule_name for m in yara.matches}
    assert "test_benign_marker" in yara_rules
    assert verdict.classification in {"unknown", "clean"}
    assert verdict.classification != "malicious"
    assert verdict.classification != "suspicious"


def test_pipeline_zip_is_clean():
    ident, _meta, _yara, verdict = _run_pipeline(str(_FIXTURES / "sample.zip"))
    assert ident.magic == "zip"
    assert verdict.classification in {"clean", "unknown"}


def test_pipeline_pdf_is_clean():
    ident, _meta, _yara, verdict = _run_pipeline(str(_FIXTURES / "sample.pdf"))
    assert ident.magic == "pdf"
    assert verdict.classification in {"clean", "unknown"}


def test_pipeline_png_is_clean():
    ident, _meta, _yara, verdict = _run_pipeline(str(_FIXTURES / "sample.png"))
    assert ident.magic == "png"
    assert verdict.classification in {"clean", "unknown"}


def test_pipeline_suspicious_file(tmp_path: Path):
    p = tmp_path / "fake.pdf"
    p.write_bytes(
        b"MZ\x90\x00"
        + b"\x00" * 100
        + b"CreateRemoteThread\x00VirtualAllocEx\x00"
        + b"powershell -enc AAAAAAAA"
    )
    ident, _meta, _yara, verdict = _run_pipeline(str(p))
    assert ident.extension_mismatch is True
    assert verdict.confidence > 0
    assert verdict.classification != "clean"


def test_pipeline_hash_matches_direct_hasher():
    path = str(_FIXTURES / "sample_pe_minimal.exe")
    _, meta, _, _ = _run_pipeline(path)
    expected = hash_file(path)
    assert meta.sha256 == expected.sha256
    assert meta.md5 == expected.md5
    assert meta.sha1 == expected.sha1


def test_pipeline_verdict_has_reasons_and_evidence():
    _, _, _, verdict = _run_pipeline(str(_FIXTURES / "sample_pe_minimal.exe"))
    assert isinstance(verdict.reasons, list)
    assert isinstance(verdict.evidence, dict)
    assert "identification" in verdict.evidence
    assert "metadata" in verdict.evidence
    assert "yara" in verdict.evidence
