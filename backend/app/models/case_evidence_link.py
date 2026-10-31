"""Case <-> Evidence junction table - Phase 11a."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.case import CaseORM


class CaseEvidenceLinkORM(Base):
    __tablename__ = "case_evidence_links"
    __table_args__ = (
        UniqueConstraint("case_id", "evidence_id", name="uq_case_evidence"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(
        ForeignKey("cases.case_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    linked_by: Mapped[str] = mapped_column(String(200), nullable=False)

    case: Mapped[CaseORM] = relationship(back_populates="evidence_links")
