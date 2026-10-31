"""Evidence ORM - Phase 11a."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class EvidenceORM(Base):
    __tablename__ = "evidence"

    evidence_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_module: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    raw_reference: Mapped[str] = mapped_column(String(500), nullable=False)
    finding: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    confidence: Mapped[int] = mapped_column(nullable=False)
    provenance: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
