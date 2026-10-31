"""Phase 1a — IOC validator tests (test-first)."""
import pytest

from app.engine.validation.ioc_validator import (
    is_valid_domain,
    is_valid_hash,
    is_valid_ipv4,
    is_valid_url,
)


# ---------- IPv4 ----------
@pytest.mark.parametrize("value", [
    "203.0.113.10",
    "8.8.8.8",
    "0.0.0.0",
    "255.255.255.255",
    "192.168.1.1",
])
def test_valid_ipv4(value):
    assert is_valid_ipv4(value) is True


@pytest.mark.parametrize("value", [
    "256.0.0.1",
    "1.2.3",
    "1.2.3.4.5",
    "01.2.3.4",          # leading zero
    "1.2.3.256",
    "1.2.3.-1",
    "abc.def.ghi.jkl",
    "",
    " 1.2.3.4",
    "1.2.3.4 ",
])
def test_invalid_ipv4(value):
    assert is_valid_ipv4(value) is False


# ---------- Domain ----------
@pytest.mark.parametrize("value", [
    "example.test",
    "example.com",
    "sub.example.co.uk",
    "a-b.example.test",
    "xn--bcher-kva.example",
])
def test_valid_domain(value):
    assert is_valid_domain(value) is True


@pytest.mark.parametrize("value", [
    "",
    "example",                # no TLD
    "-example.com",           # leading hyphen
    "example-.com",           # trailing hyphen
    "exa mple.com",           # space
    "example..com",           # empty label
    "a" * 64 + ".com",        # label > 63
    ".".join(["a"] * 130),    # total > 253
    "example.c",              # TLD < 2
    "exa_mple.com",           # underscore
])
def test_invalid_domain(value):
    assert is_valid_domain(value) is False


# ---------- URL ----------
@pytest.mark.parametrize("value", [
    "http://example.test",
    "https://example.test/path",
    "https://example.test/login?next=/dashboard",
    "hxxp://example.test",
    "hxxps://account-update.example.test/login",
])
def test_valid_url(value):
    assert is_valid_url(value) is True


@pytest.mark.parametrize("value", [
    "",
    "example.test",                 # no scheme
    "ftp://example.test",           # unsupported scheme
    "http://",                      # no host
    "https://exa mple.test",        # space in host
    "https://-bad.test",            # host leading hyphen
])
def test_invalid_url(value):
    assert is_valid_url(value) is False


# ---------- Hash ----------
@pytest.mark.parametrize("value,algo", [
    ("44d88612fea8a8f36de82e1278abb02f", "md5"),
    ("44D88612FEA8A8F36DE82E1278ABB02F", "md5"),   # uppercase ok
    ("a" * 40, "sha1"),
    ("a" * 64, "sha256"),
    ("44d88612fea8a8f36de82e1278abb02f", None),    # auto-detect
    ("a" * 64, None),
])
def test_valid_hash(value, algo):
    assert is_valid_hash(value, algo) is True


@pytest.mark.parametrize("value,algo", [
    ("", None),
    ("xyz", None),
    ("a" * 31, None),                # wrong length
    ("a" * 32, "sha1"),              # length mismatch
    ("g" * 32, "md5"),               # non-hex
    ("44d88612fea8a8f36de82e1278abb02", "md5"),  # 31 chars
])
def test_invalid_hash(value, algo):
    assert is_valid_hash(value, algo) is False
