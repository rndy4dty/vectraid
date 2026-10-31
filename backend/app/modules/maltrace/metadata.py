"""MalTrace metadata extraction - Phase 4b.

Extracts file hashes (via Phase 1c hasher), PE metadata (via pefile),
and printable strings. Pure static analysis - no execution.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import pefile

from app.engine.hashing.hasher import hash_file


@dataclass(frozen=True)
class PEInfo:
    machine: str
    subsystem: str
    timestamp: int
    entry_point: int
    section_count: int
    imported_dlls: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FileMetadata:
    path: str
    size: int
    md5: str
    sha1: str
    sha256: str
    pe_info: PEInfo | None
    strings_sample: list[str]
    strings_truncated: bool
    error: str | None


_MACHINE_MAP = {
    0x14C: "x86",
    0x8664: "x64",
    0xAA64: "arm64",
    0x1C0: "arm",
}

_SUBSYSTEM_MAP = {
    1: "native",
    2: "GUI",
    3: "CLI",
}

_PRINTABLE_RE = re.compile(rb"[\x20-\x7E]{6,}")


def extract_metadata(
    path: str,
    *,
    strings_limit: int = 100,
    scan_bytes_limit: int = 5_000_000,
) -> FileMetadata:
    """Extract hashes, PE info, and printable strings. Never raises on parse errors."""
    p = Path(path)
    size = p.stat().st_size

    hashes = hash_file(str(p))

    # Read up to scan_bytes_limit for strings + PE parse
    with p.open("rb") as fh:
        raw = fh.read(scan_bytes_limit)
    strings_truncated = size > scan_bytes_limit

    strings = _extract_strings(raw, strings_limit)

    pe_info, error = _extract_pe_info(raw)

    return FileMetadata(
        path=str(p),
        size=size,
        md5=hashes.md5,
        sha1=hashes.sha1,
        sha256=hashes.sha256,
        pe_info=pe_info,
        strings_sample=strings,
        strings_truncated=strings_truncated,
        error=error,
    )


def _extract_strings(raw: bytes, limit: int) -> list[str]:
    if limit <= 0:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for match in _PRINTABLE_RE.finditer(raw):
        s = match.group(0).decode("ascii", errors="replace")
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= limit:
            break
    return out


def _extract_pe_info(raw: bytes) -> tuple[PEInfo | None, str | None]:
    if not raw.startswith(b"MZ"):
        return None, None
    try:
        pe = pefile.PE(data=raw, fast_load=True)
    except Exception as exc:  # noqa: BLE001 - fail-soft
        return None, f"pe_parse_failed: {type(exc).__name__}"

    try:
        machine_raw = pe.FILE_HEADER.Machine
        subsystem_raw = pe.OPTIONAL_HEADER.Subsystem
        pe_info = PEInfo(
            machine=_MACHINE_MAP.get(machine_raw, f"unknown:{machine_raw:#x}"),
            subsystem=_SUBSYSTEM_MAP.get(subsystem_raw, f"unknown:{subsystem_raw}"),
            timestamp=int(pe.FILE_HEADER.TimeDateStamp),
            entry_point=int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            section_count=int(pe.FILE_HEADER.NumberOfSections),
            imported_dlls=_imported_dlls(pe, limit=50),
        )
    except Exception as exc:  # noqa: BLE001 - fail-soft
        pe.close()
        return None, f"pe_info_extract_failed: {type(exc).__name__}"
    finally:
        pe.close()

    return pe_info, None


def _imported_dlls(pe: pefile.PE, limit: int) -> list[str]:
    # Imports are not parsed under fast_load; parse them on demand.
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]],
        )
    except Exception:  # noqa: BLE001 - fail-soft
        return []

    entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []
    dlls: list[str] = []
    for entry in entries:
        name = getattr(entry, "dll", None)
        if isinstance(name, bytes):
            name = name.decode("ascii", errors="replace")
        if name:
            dlls.append(name)
        if len(dlls) >= limit:
            break
    return dlls
