"""Phase 1d - IOC extractor tests (test-first).

Extractor is permissive: it collects candidates, then filters via
validators. It never raises on bad input; errors go to result.errors.
"""

from app.engine.extraction.ioc_extractor import (
    ExtractedIOC,
    ExtractionResult,
    extract_iocs,
)


# ---------- basic extraction ----------
def test_extract_ipv4():
    result = extract_iocs("Found C2 at 203.0.113.10 today", source="manual")
    values = {i.value for i in result.iocs}
    assert "203.0.113.10" in values
    types = {i.ioc_type for i in result.iocs if i.value == "203.0.113.10"}
    assert types == {"ipv4"}


def test_extract_domain():
    result = extract_iocs("Visit example.test for details", source="manual")
    values = {i.value for i in result.iocs}
    assert "example.test" in values


def test_extract_url():
    result = extract_iocs("C2: https://malicious.example.test/login", source="manual")
    values = {i.value for i in result.iocs}
    assert "https://malicious.example.test/login" in values


def test_extract_email():
    result = extract_iocs("Sender notification@example.test is suspicious", source="manual")
    values = {i.value for i in result.iocs}
    assert "notification@example.test" in values


def test_extract_md5():
    result = extract_iocs("Hash: 44d88612fea8a8f36de82e1278abb02f", source="manual")
    values = {i.value for i in result.iocs}
    assert "44d88612fea8a8f36de82e1278abb02f" in values


def test_extract_sha256():
    h = "a" * 64
    result = extract_iocs(f"Sample hash {h}", source="manual")
    assert h in {i.value for i in result.iocs}


# ---------- multiple IOCs in one blob ----------
def test_extract_multiple_mixed():
    text = (
        "IOC: 203.0.113.10 and example.test and user@example.test "
        "and https://bad.example.test/x and 44d88612fea8a8f36de82e1278abb02f"
    )
    result = extract_iocs(text, source="manual")
    values = {i.value for i in result.iocs}
    assert "203.0.113.10" in values
    assert "example.test" in values
    assert "user@example.test" in values
    assert "https://bad.example.test/x" in values
    assert "44d88612fea8a8f36de82e1278abb02f" in values


# ---------- dedup ----------
def test_extract_dedupes_identical():
    text = "203.0.113.10 203.0.113.10 203.0.113.10"
    result = extract_iocs(text, source="manual")
    ipv4_values = [i.value for i in result.iocs if i.ioc_type == "ipv4"]
    assert ipv4_values.count("203.0.113.10") == 1


# ---------- refang ----------
def test_extract_refangs_hxxp_url():
    text = "C2: hxxps://bad.example.test/login"
    result = extract_iocs(text, source="manual")
    # Extractor should refang to https:// and record that.
    values = {i.value for i in result.iocs}
    assert "https://bad.example.test/login" in values


def test_extract_refangs_dot_defang():
    text = "Domain: example[.]test"
    result = extract_iocs(text, source="manual")
    values = {i.value for i in result.iocs}
    assert "example.test" in values


# ---------- source label ----------
def test_extract_source_label_propagates():
    result = extract_iocs("203.0.113.10", source="eml:header")
    for ioc in result.iocs:
        if ioc.value == "203.0.113.10":
            assert ioc.source == "eml:header"


# ---------- errors ----------
def test_extract_empty_returns_empty():
    result = extract_iocs("", source="manual")
    assert isinstance(result, ExtractionResult)
    assert result.iocs == []


def test_extract_none_returns_error():
    result = extract_iocs(None, source="manual")  # type: ignore[arg-type]
    assert isinstance(result, ExtractionResult)
    assert result.iocs == []
    assert result.errors


def test_extract_does_not_raise_on_garbage():
    # Should not raise; errors list may or may not be populated.
    result = extract_iocs("\x00\x01\x02 not really text", source="manual")
    assert isinstance(result, ExtractionResult)


# ---------- fields ----------
def test_extracted_ioc_has_expected_fields():
    ioc = ExtractedIOC(value="example.test", ioc_type="domain", source="manual")
    assert ioc.value == "example.test"
    assert ioc.ioc_type == "domain"
    assert ioc.source == "manual"
    assert ioc.raw_context == ""
