"""Hash calculator — Phase 1."""
from dataclasses import dataclass


@dataclass
class HashResult:
    md5: str
    sha1: str
    sha256: str


def hash_bytes(data: bytes) -> HashResult:
    raise NotImplementedError("Phase 1 — to be implemented")


def hash_file(path: str) -> HashResult:
    raise NotImplementedError("Phase 1 — to be implemented")
