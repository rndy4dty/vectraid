"""MalTrace file identifier - Phase 4a.

Identifies file type from magic bytes and detects extension mismatch.
No execution, no network, no content inspection beyond the first bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileIdentification:
    magic: str          # zip | pdf | png | jpeg | gif | pe | elf | unknown
    mime: str           # application/zip | application/pdf | ...
    extension: str      # lowercase, tanpa titik ("" jika tidak ada)
    extension_mismatch: bool
    size: int
    path: str


# Signature table. Order matters: longer/earlier matches first.
# Format: (magic_bytes, magic_name, mime)
_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"PK\x03\x04", "zip", "application/zip"),
    (b"%PDF", "pdf", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "png", "image/png"),
    (b"\xff\xd8\xff", "jpeg", "image/jpeg"),
    (b"GIF87a", "gif", "image/gif"),
    (b"GIF89a", "gif", "image/gif"),
    (b"MZ", "pe", "application/x-dosexec"),
    (b"\x7fELF", "elf", "application/x-elf"),
]

# Extension -> expected magic(s). Used to flag mismatches.
_EXT_EXPECTED_MAGIC: dict[str, set[str]] = {
    "zip": {"zip"},
    "pdf": {"pdf"},
    "png": {"png"},
    "jpg": {"jpeg"},
    "jpeg": {"jpeg"},
    "gif": {"gif"},
    "exe": {"pe"},
    "dll": {"pe"},
    "elf": {"elf"},
    "so": {"elf"},
}

_TEXT_EXTS = {"txt", "md", "log", "csv", "json", "xml", "yaml", "yml"}

_UNKNOWN_MIME = "application/octet-stream"
_MIN_BYTES = 4  # fewer bytes -> unknown


def identify_file(path: str) -> FileIdentification:
    """Identify a file by its magic bytes and detect extension mismatch."""
    p = Path(path)
    size = p.stat().st_size

    # Read only the first 16 bytes - enough for every signature.
    with p.open("rb") as fh:
        head = fh.read(16)

    magic, mime = _classify(head)

    extension = p.suffix.lower().lstrip(".")

    mismatch = _is_mismatch(extension, magic)

    return FileIdentification(
        magic=magic,
        mime=mime,
        extension=extension,
        extension_mismatch=mismatch,
        size=size,
        path=str(p),
    )


def _classify(head: bytes) -> tuple[str, str]:
    if len(head) < _MIN_BYTES:
        return "unknown", _UNKNOWN_MIME
    for sig, name, mime in _SIGNATURES:
        if head.startswith(sig):
            return name, mime
    # No magic match. Could still be text (heuristic on printable bytes).
    if _looks_like_text(head):
        return "text", "text/plain"
    return "unknown", _UNKNOWN_MIME


def _looks_like_text(head: bytes) -> bool:
    if not head:
        return False
    printable = sum(1 for b in head if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / len(head) >= 0.9


def _is_mismatch(extension: str, magic: str) -> bool:
    """Return True if the extension claims something the magic bytes deny."""
    if not extension:
        return False
    expected = _EXT_EXPECTED_MAGIC.get(extension)
    if expected is not None:
        return magic not in expected
    if extension in _TEXT_EXTS:
        # Text extensions should not claim to be a binary format.
        return magic in {"zip", "pdf", "png", "jpeg", "gif", "pe", "elf"}
    # Unknown extension: no basis to claim mismatch.
    return False
