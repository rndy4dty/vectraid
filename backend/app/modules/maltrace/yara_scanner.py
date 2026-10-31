"""MalTrace YARA scanner - Phase 4c.

Compiles YARA rules from a directory and scans files. Fail-soft: rule
compile errors and match timeouts become fields on the result, not crashes.
No execution. No network.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yara

_DEFAULT_RULES_DIR = Path(__file__).parent / "rules"


@dataclass(frozen=True)
class YaraMatch:
    rule_name: str
    tags: list[str]
    meta: dict
    strings_matched: list[str]


@dataclass(frozen=True)
class YaraScanResult:
    matches: list[YaraMatch] = field(default_factory=list)
    scanned_path: str = ""
    error: str | None = None
    timed_out: bool = False


def compile_rules(rules_dir: str | None = None) -> yara.Rules:
    """Compile all .yar/.yara files from a directory into a single Rules object.

    Raises:
        FileNotFoundError: if the directory does not exist.
        ValueError: if no rule files are found.
        yara.SyntaxError: if any rule fails to compile.
    """
    base = Path(rules_dir) if rules_dir else _DEFAULT_RULES_DIR
    if not base.is_dir():
        raise FileNotFoundError(f"rules dir not found: {base}")

    filepaths: dict[str, str] = {}
    for pattern in ("*.yar", "*.yara"):
        for f in sorted(base.glob(pattern)):
            filepaths[f.stem] = str(f)

    if not filepaths:
        raise ValueError(f"no rule files found in {base}")

    return yara.compile(filepaths=filepaths)


def scan_file(
    path: str,
    rules: yara.Rules,
    *,
    timeout: int = 10,
) -> YaraScanResult:
    """Scan a file with compiled rules. Raises FileNotFoundError if missing."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)

    try:
        raw_matches = rules.match(str(p), timeout=timeout)
    except yara.TimeoutError:
        return YaraScanResult(
            matches=[],
            scanned_path=str(p),
            error="timeout",
            timed_out=True,
        )
    except Exception as exc:  # noqa: BLE001 - fail-soft
        return YaraScanResult(
            matches=[],
            scanned_path=str(p),
            error=f"scan_failed: {type(exc).__name__}",
            timed_out=False,
        )

    matches = [_convert(m) for m in raw_matches]
    return YaraScanResult(
        matches=matches,
        scanned_path=str(p),
        error=None,
        timed_out=False,
    )


def _convert(match: yara.Match) -> YaraMatch:
    tags = list(match.tags) if match.tags else []
    meta = dict(match.meta) if match.meta else {}

    strings_matched: list[str] = []
    for s in getattr(match, "strings", []) or []:
        # s is (offset, identifier, data) in yara-python >= 4.x
        try:
            offset = s.instances[0].offset if hasattr(s, "instances") else s[0]
            identifier = s.identifier if hasattr(s, "identifier") else s[1]
        except Exception:  # noqa: BLE001 - fail-soft
            continue
        strings_matched.append(f"{identifier}@{offset}")

    return YaraMatch(
        rule_name=match.rule,
        tags=tags,
        meta=meta,
        strings_matched=strings_matched,
    )
