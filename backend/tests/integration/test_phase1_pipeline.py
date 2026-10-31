"""Phase 1 integration test - end-to-end Core Engine against real fixture.

Reads tests/fixtures/iocs/sample_iocs.txt, extracts IOCs, normalizes,
and compares against datasets/expected-results/sample_iocs.expected.json.
"""
import json
from pathlib import Path

from app.engine.extraction.ioc_extractor import extract_iocs
from app.engine.hashing.hasher import hash_bytes
from app.engine.normalization.ioc_normalizer import normalize

_BACKEND = Path(__file__).resolve().parents[2]
_FIXTURE = _BACKEND / "tests" / "fixtures" / "iocs" / "sample_iocs.txt"
_EXPECTED = _BACKEND.parent / "datasets" / "expected-results" / "sample_iocs.expected.json"


def test_fixture_files_exist():
    assert _FIXTURE.is_file(), f"missing fixture: {_FIXTURE}"
    assert _EXPECTED.is_file(), f"missing expected: {_EXPECTED}"


def test_extract_matches_expected():
    text = _FIXTURE.read_text()
    expected = json.loads(_EXPECTED.read_text())
    result = extract_iocs(text, source="fixture:sample_iocs")

    got = {(i.value.lower(), i.ioc_type) for i in result.iocs}
    for item in expected["expected_iocs"]:
        key = (item["value"].lower(), item["type"])
        assert key in got, f"missing IOC: {item}"


def test_extracted_iocs_all_normalize_without_error():
    text = _FIXTURE.read_text()
    result = extract_iocs(text, source="fixture:sample_iocs")
    for ioc in result.iocs:
        # All extracted values must normalize cleanly for their type.
        normalized = normalize(ioc.value, ioc.ioc_type)
        assert normalized, f"normalize returned empty for {ioc}"


def test_hasher_smoke_on_fixture_bytes():
    data = _FIXTURE.read_bytes()
    r = hash_bytes(data)
    assert len(r.md5) == 32
    assert len(r.sha1) == 40
    assert len(r.sha256) == 64
    # Deterministic
    assert r == hash_bytes(data)
