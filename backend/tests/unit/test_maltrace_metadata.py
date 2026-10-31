"""Phase 4b - MalTrace metadata extraction tests (test-first)."""
from pathlib import Path

from app.modules.maltrace.metadata import (
    FileMetadata,
    PEInfo,
    extract_metadata,
)

_FIXTURES = (
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "malware"
)


# ---------- dataclass shapes ----------
def test_file_metadata_fields():
    m = FileMetadata(
        path="x",
        size=1,
        md5="a",
        sha1="b",
        sha256="c",
        pe_info=None,
        strings_sample=[],
        strings_truncated=False,
        error=None,
    )
    assert m.size == 1
    assert m.pe_info is None


def test_pe_info_fields():
    p = PEInfo(
        machine="x86",
        subsystem="CLI",
        timestamp=0,
        entry_point=0x1000,
        section_count=1,
        imported_dlls=[],
    )
    assert p.machine == "x86"
    assert p.entry_point == 0x1000


# ---------- text file ----------
def test_extract_metadata_text_file():
    m = extract_metadata(str(_FIXTURES / "text.txt"))
    assert m.size > 0
    assert len(m.md5) == 32
    assert len(m.sha1) == 40
    assert len(m.sha256) == 64
    assert m.pe_info is None
    assert m.error is None


def test_extract_metadata_strings_from_text():
    m = extract_metadata(str(_FIXTURES / "text.txt"))
    # "This is a benign text file for testing." has long printable runs
    assert any("benign" in s for s in m.strings_sample)


# ---------- PE file ----------
def test_extract_metadata_pe_returns_pe_info():
    m = extract_metadata(str(_FIXTURES / "sample_pe_minimal.exe"))
    assert m.pe_info is not None
    assert isinstance(m.pe_info, PEInfo)
    assert m.pe_info.machine == "x86"
    assert m.pe_info.subsystem == "CLI"
    assert m.pe_info.section_count == 1
    assert m.error is None


def test_extract_metadata_pe_hashes_match_file():
    """Hashes must match hashing the raw bytes directly."""
    from app.engine.hashing.hasher import hash_file

    path = str(_FIXTURES / "sample_pe_minimal.exe")
    m = extract_metadata(path)
    expected = hash_file(path)
    assert m.md5 == expected.md5
    assert m.sha1 == expected.sha1
    assert m.sha256 == expected.sha256


# ---------- non-PE with .exe extension: PE parse fails, hash still present ----------
def test_extract_metadata_non_pe_exe_survives():
    """sample.exe is MZ but not a valid PE. Metadata must still be returned."""
    m = extract_metadata(str(_FIXTURES / "sample.exe"))
    assert len(m.sha256) == 64
    # pe_info may be None or may parse partially; error may be set.
    # At minimum, metadata is returned without raising.


# ---------- missing file ----------
def test_extract_metadata_missing_raises():
    import pytest

    with pytest.raises(FileNotFoundError):
        extract_metadata("/nonexistent/path/file.bin")


# ---------- strings limit ----------
def test_extract_metadata_respects_strings_limit():
    m = extract_metadata(str(_FIXTURES / "text.txt"), strings_limit=2)
    assert len(m.strings_sample) <= 2


# ---------- scan limit ----------
def test_extract_metadata_marks_truncation_when_limited():
    m = extract_metadata(
        str(_FIXTURES / "sample_pe_minimal.exe"),
        scan_bytes_limit=8,
    )
    assert m.strings_truncated is True
