"""MalTrace classification - Phase 4d.

Combines file identification, metadata, and YARA results into a single
verdict with explicit reasons. Pure function: no I/O, no side effects.

Classification levels mirror ProviderResponse (Phase 2):
  malicious | suspicious | clean | unknown

No single signal is enough for 'malicious'. Confidence accumulates from
multiple independent signals. Absence of evidence -> 'unknown', not 'clean'.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.modules.maltrace.identifier import FileIdentification
from app.modules.maltrace.metadata import FileMetadata
from app.modules.maltrace.yara_scanner import YaraScanResult

# Contribution per signal. Calibrated in Phase 7 with datasets.
_WEIGHTS = {
    "yara_high": 50,
    "yara_medium": 30,
    "yara_info": 5,
    "extension_mismatch": 20,
    "import_injection": 25,
    "import_exec": 15,
    "strings_powershell_enc": 20,
    "strings_url": 10,
}

# Verdict thresholds. 'malicious' requires >= 70.
_THRESHOLDS = {
    "malicious": 70,
    "suspicious": 40,
    "unknown": 10,  # >= 10 but < 40 -> unknown (weak signal, not verdict)
}

_INJECTION_APIS = frozenset({"CreateRemoteThread", "VirtualAllocEx"})
_EXEC_APIS = frozenset(
    {
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "CreateProcessA",
        "CreateProcessW",
    }
)


@dataclass(frozen=True)
class ClassificationResult:
    classification: str  # malicious | suspicious | clean | unknown
    confidence: int      # 0-100
    reasons: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


def classify_file(
    identification: FileIdentification,
    metadata: FileMetadata,
    yara_result: YaraScanResult,
) -> ClassificationResult:
    """Combine signals into a verdict. Pure function."""
    score = 0
    reasons: list[str] = []

    # --- YARA matches ---
    for m in yara_result.matches:
        severity = (m.meta or {}).get("severity", "").lower()
        if severity == "high":
            score += _WEIGHTS["yara_high"]
            reasons.append(f"YARA rule '{m.rule_name}' matched with severity=high")
        elif severity == "medium":
            score += _WEIGHTS["yara_medium"]
            reasons.append(f"YARA rule '{m.rule_name}' matched with severity=medium")
        elif severity == "info":
            score += _WEIGHTS["yara_info"]
            reasons.append(f"YARA rule '{m.rule_name}' matched with severity=info")

    # --- Extension mismatch ---
    if identification.extension_mismatch:
        score += _WEIGHTS["extension_mismatch"]
        reasons.append(
            f"Extension mismatch: file claims '{identification.extension}' "
            f"but magic bytes say '{identification.magic}'"
        )

    # --- PE imports ---
    if metadata.pe_info is not None:
        imports = set(metadata.pe_info.imported_dlls)
        if imports & _INJECTION_APIS:
            score += _WEIGHTS["import_injection"]
            hits = sorted(imports & _INJECTION_APIS)
            reasons.append(f"PE imports injection-related API(s): {hits}")
        if imports & _EXEC_APIS:
            score += _WEIGHTS["import_exec"]
            hits = sorted(imports & _EXEC_APIS)
            reasons.append(f"PE imports process execution API(s): {hits}")

    # --- Suspicious strings ---
    joined = " ".join(metadata.strings_sample).lower()
    ps_enc = (
        "powershell -enc" in joined
        or "powershell.exe -enc" in joined
        or "-encodedcommand" in joined
    )
    if ps_enc:
        score += _WEIGHTS["strings_powershell_enc"]
        reasons.append("Strings contain encoded PowerShell invocation")
    if "http://" in joined or "https://" in joined:
        score += _WEIGHTS["strings_url"]
        reasons.append("Strings contain HTTP(S) URL (possible C2 indicator)")

    # Clamp to 0-100
    confidence = max(0, min(100, score))

    # --- Determine classification ---
    if confidence >= _THRESHOLDS["malicious"]:
        classification = "malicious"
    elif confidence >= _THRESHOLDS["suspicious"]:
        classification = "suspicious"
    elif confidence >= _THRESHOLDS["unknown"]:
        # Signals exist but weak.
        classification = "unknown"
    else:
        # No strong signals. Was there any positive identification at all?
        # If the file is a recognizable non-PE (text, pdf, png, etc.) -> clean.
        # If we have no info at all -> unknown.
        if identification.magic in {"unknown", "text"} and metadata.pe_info is None:
            classification = "unknown"
        else:
            classification = "clean"
            reasons.append("No suspicious signals; file identified but not flagged")

    return ClassificationResult(
        classification=classification,
        confidence=confidence,
        reasons=reasons,
        evidence={
            "identification": {
                "magic": identification.magic,
                "mime": identification.mime,
                "extension": identification.extension,
                "extension_mismatch": identification.extension_mismatch,
            },
            "metadata": {
                "size": metadata.size,
                "sha256": metadata.sha256,
                "has_pe_info": metadata.pe_info is not None,
                "strings_count": len(metadata.strings_sample),
            },
            "yara": {
                "match_count": len(yara_result.matches),
                "rule_names": [m.rule_name for m in yara_result.matches],
            },
        },
    )
