"""PDF report generator - Phase 11b.

Renders the case + investigation report into a PDF using Jinja2 + WeasyPrint.
Pure function: takes domain objects, returns bytes.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

from app.modules.investigation.case import Case
from app.modules.investigation.engine import InvestigationReport

_TEMPLATE_DIR = Path(__file__).parent
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def _status_class(status: str) -> str:
    return {
        "new": "info",
        "investigating": "medium",
        "resolved": "low",
        "closed": "muted",
    }.get(status.lower(), "muted")


def _priority_class(priority: str) -> str:
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }.get(priority.lower(), "muted")


def _risk_class(risk: str) -> str:
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
        "insufficient_data": "muted",
    }.get(risk.lower(), "muted")


def generate_case_pdf(
    case: Case,
    report: InvestigationReport,
) -> bytes:
    """Render the case + investigation report to PDF bytes."""
    template = _env.get_template("template.html")
    html_str = template.render(
        case=case,
        report=report,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        status_class=_status_class,
        priority_class=_priority_class,
        risk_class=_risk_class,
    )
    return HTML(string=html_str).write_pdf()
