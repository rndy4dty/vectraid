"""Phase 1c - Hasher tests (test-first).

Deterministic MD5/SHA1/SHA256 over bytes and files.
"""
from pathlib import Path

import pytest

from app.engine.hashing.hasher import HashResult, hash_bytes, hash_file

# ---------- known-answer vectors ----------
# Empty input
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# b"abc"
ABC_MD5 = "900150983cd24fb0d6963f7d28e17f72"
ABC_SHA1 = "a9993e364706816aba3e25717850c26c9cd0d89d"
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hash_result_is_dataclass():
    r = HashResult(md5="a", sha1="b", sha256="c")
    assert r.md5 == "a"
    assert r.sha1 == "b"
    assert r.sha256 == "c"


def test_hash_bytes_empty():
    r = hash_bytes(b"")
    assert r.md5 == EMPTY_MD5
    assert r.sha1 == EMPTY_SHA1
    assert r.sha256 == EMPTY_SHA256


def test_hash_bytes_abc():
    r = hash_bytes(b"abc")
    assert r.md5 == ABC_MD5
    assert r.sha1 == ABC_SHA1
    assert r.sha256 == ABC_SHA256


def test_hash_bytes_deterministic():
    a = hash_bytes(b"hello world")
    b = hash_bytes(b"hello world")
    assert a == b


def test_hash_bytes_different_inputs():
    a = hash_bytes(b"abc")
    b = hash_bytes(b"abd")
    assert a.sha256 != b.sha256


def test_hash_file_matches_hash_bytes(tmp_path: Path):
    data = b"the quick brown fox jumps over the lazy dog"
    p = tmp_path / "sample.bin"
    p.write_bytes(data)

    from_file = hash_file(str(p))
    from_bytes = hash_bytes(data)
    assert from_file == from_bytes


def test_hash_file_empty(tmp_path: Path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    r = hash_file(str(p))
    assert r.md5 == EMPTY_MD5
    assert r.sha1 == EMPTY_SHA1
    assert r.sha256 == EMPTY_SHA256


def test_hash_file_streaming_large(tmp_path: Path):
    # 1 MiB of deterministic data; exercises chunked read path.
    data = bytes(range(256)) * 4096
    p = tmp_path / "large.bin"
    p.write_bytes(data)

    from_file = hash_file(str(p))
    from_bytes = hash_bytes(data)
    assert from_file == from_bytes


def test_hash_file_missing():
    with pytest.raises(FileNotFoundError):
        hash_file("/nonexistent/path/does/not/exist.bin")


def test_hash_result_fields_are_lowercase_hex():
    r = hash_bytes(b"abc")
    for value in (r.md5, r.sha1, r.sha256):
        assert value == value.lower()
        assert all(c in "0123456789abcdef" for c in value)
