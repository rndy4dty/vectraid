"""Hash calculator - Phase 1.

Deterministic MD5/SHA1/SHA256 over bytes and files.
Streaming file reads use a 64 KiB chunk to avoid loading large files
into memory. No network, no side effects.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

_CHUNK_SIZE = 65536  # 64 KiB


@dataclass
class HashResult:
    md5: str
    sha1: str
    sha256: str


def hash_bytes(data: bytes) -> HashResult:
    """Hash raw bytes and return all three digests."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("hash_bytes expects bytes-like input")
    payload = bytes(data)
    return HashResult(
        md5=hashlib.md5(payload).hexdigest(),
        sha1=hashlib.sha1(payload).hexdigest(),
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def hash_file(path: str) -> HashResult:
    """Stream-hash a file, returning all three digests.

    Raises:
        FileNotFoundError: if the file does not exist.
        IsADirectoryError: if path points to a directory.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return HashResult(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
    )
