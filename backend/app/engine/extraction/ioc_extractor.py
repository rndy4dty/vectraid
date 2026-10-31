"""IOC extractor — Phase 1."""
from dataclasses import dataclass, field


@dataclass
class ExtractedIOC:
    value: str
    ioc_type: str
    source: str
    raw_context: str = ""


@dataclass
class ExtractionResult:
    iocs: list[ExtractedIOC] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def extract_iocs(text: str, source: str = "manual") -> ExtractionResult:
    raise NotImplementedError("Phase 1 — to be implemented")
