"""Phase 1b - IOC normalizer tests (test-first).

Pure, deterministic normalization. No network, no side effects.
All assertions avoid non-ASCII characters in strings.
"""
import pytest

from app.engine.normalization.ioc_normalizer import normalize


# ---------- domain ----------
@pytest.mark.parametrize("raw,expected", [
    ("Example.TEST", "example.test"),
    ("EXAMPLE.COM", "example.com"),
    ("sub.Example.Co.UK", "sub.example.co.uk"),
    ("example.test.", "example.test"),          # trailing dot stripped
    ("  example.test  ", "example.test"),       # whitespace stripped
    ("a-b.example.test", "a-b.example.test"),   # already canonical
])
def test_normalize_domain(raw, expected):
    assert normalize(raw, "domain") == expected


# ---------- ipv4 ----------
@pytest.mark.parametrize("raw,expected", [
    ("203.0.113.10", "203.0.113.10"),
    ("  203.0.113.10  ", "203.0.113.10"),
    ("8.8.8.8", "8.8.8.8"),
])
def test_normalize_ipv4(raw, expected):
    assert normalize(raw, "ipv4") == expected


# ---------- url ----------
@pytest.mark.parametrize("raw,expected", [
    ("HTTPS://Example.TEST/Path", "https://example.test/Path"),
    ("http://EXAMPLE.test/login?Next=/x", "http://example.test/login?Next=/x"),
    ("https://example.test/path#frag", "https://example.test/path"),
    ("  https://example.test/path  ", "https://example.test/path"),
    ("hxxps://Example.test/login", "hxxps://example.test/login"),
])
def test_normalize_url(raw, expected):
    assert normalize(raw, "url") == expected


# ---------- hashes (satu parametrize per algo) ----------
@pytest.mark.parametrize("raw,expected", [
    ("44D88612FEA8A8F36DE82E1278ABB02F", "44d88612fea8a8f36de82e1278abb02f"),
    ("a" * 32, "a" * 32),
])
def test_normalize_md5(raw, expected):
    assert normalize(raw, "md5") == expected


@pytest.mark.parametrize("raw,expected", [
    ("A" * 40, "a" * 40),
])
def test_normalize_sha1(raw, expected):
    assert normalize(raw, "sha1") == expected


@pytest.mark.parametrize("raw,expected", [
    ("B" * 64, "b" * 64),
])
def test_normalize_sha256(raw, expected):
    assert normalize(raw, "sha256") == expected


# ---------- email ----------
@pytest.mark.parametrize("raw,expected", [
    ("User@Example.TEST", "User@example.test"),   # local-part case preserved
    ("user@EXAMPLE.COM", "user@example.com"),
    ("  user@example.test  ", "user@example.test"),
])
def test_normalize_email(raw, expected):
    assert normalize(raw, "email") == expected


# ---------- edge cases ----------
def test_normalize_unknown_type_raises():
    with pytest.raises(ValueError):
        normalize("x", "unknown-type")


def test_normalize_empty_raises():
    with pytest.raises(ValueError):
        normalize("", "domain")


def test_normalize_idempotent():
    samples = [
        ("Example.TEST", "domain"),
        ("HTTPS://Example.TEST/Path", "url"),
        ("44D88612FEA8A8F36DE82E1278ABB02F", "md5"),
        ("User@Example.TEST", "email"),
    ]
    for raw, kind in samples:
        once = normalize(raw, kind)
        twice = normalize(once, kind)
        assert once == twice, f"not idempotent for {kind}: {raw!r}"
