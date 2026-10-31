"""Phase 4a - MalTrace file identification tests (test-first)."""
from pathlib import Path

import pytest

from app.modules.maltrace.identifier import (
    FileIdentification,
    identify_file,
)

_FIXTURES = (
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "malware"
)


def test_identify_returns_dataclass():
    result = identify_file(str(_FIXTURES / "text.txt"))
    assert isinstance(result, FileIdentification)


def test_identify_zip():
    result = identify_file(str(_FIXTURES / "sample.zip"))
    assert result.mime == "application/zip"
    assert result.magic == "zip"
    assert result.extension_mismatch is False


def test_identify_pdf():
    result = identify_file(str(_FIXTURES / "sample.pdf"))
    assert result.mime == "application/pdf"
    assert result.magic == "pdf"
    assert result.extension_mismatch is False


def test_identify_png():
    result = identify_file(str(_FIXTURES / "sample.png"))
    assert result.mime == "image/png"
    assert result.magic == "png"
    assert result.extension_mismatch is False


def test_identify_pe_mz():
    result = identify_file(str(_FIXTURES / "sample.exe"))
    assert result.mime == "application/x-dosexec"
    assert result.magic == "pe"
    assert result.extension_mismatch is False


def test_identify_text_unknown_magic():
    result = identify_file(str(_FIXTURES / "text.txt"))
    assert result.extension_mismatch is False
    assert result.mime in {"text/plain", "application/octet-stream"}


def test_extension_mismatch_detected():
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(b"PK\x03\x04\x14\x00\x00\x00\x00\x00")
        tmp_path = f.name
    try:
        result = identify_file(tmp_path)
        assert result.magic == "zip"
        assert result.extension_mismatch is True
    finally:
        Path(tmp_path).unlink()


def test_identify_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        identify_file("/nonexistent/path/file.bin")


def test_identify_small_file_returns_unknown():
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"AB")
        tmp_path = f.name
    try:
        result = identify_file(tmp_path)
        assert result.magic == "unknown"
        assert result.mime == "application/octet-stream"
    finally:
        Path(tmp_path).unlink()
