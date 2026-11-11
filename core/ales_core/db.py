"""SQLAlchemy ORM tables. Engine-agnostic (SQLite for tests, Postgres in prod)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Engine,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC datetimes on every backend (SQLite drops tzinfo otherwise)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    tenant_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    revocation_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ContextObject(Base):
    __tablename__ = "context_objects"
    context_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    object_version: Mapped[str] = mapped_column(String(255), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), ForeignKey("tenants.tenant_id"), nullable=False)
    object_id: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    content_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    trust_state: Mapped[str] = mapped_column(String(32), nullable=False)
    principal_scope: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    purpose_scope: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    valid_from: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    source_system: Mapped[str] = mapped_column(String(255), nullable=False)
    source_acl_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False, default="p0")
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    tombstoned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tombstone_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)

    __table_args__ = (Index("ix_context_objects_tenant", "tenant_id", "context_id"),)


class DerivationEdge(Base):
    __tablename__ = "derivation_edges"
    child_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    child_version: Mapped[str] = mapped_column(String(255), primary_key=True)
    parent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    parent_version: Mapped[str] = mapped_column(String(255), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["child_id", "child_version"],
            ["context_objects.context_id", "context_objects.object_version"],
        ),
        Index("ix_edges_parent", "tenant_id", "parent_id", "parent_version"),
        Index("ix_edges_child", "tenant_id", "child_id", "child_version"),
    )


class RevocationEventRow(Base):
    __tablename__ = "revocation_events"
    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason: Mapped[str] = mapped_column(String(32), nullable=False)
    effective_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    source_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    affected_scope: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    accepted_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    resulting_epoch: Mapped[int] = mapped_column(Integer, nullable=False)


class InvalidationOutbox(Base):
    __tablename__ = "invalidation_outbox"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    context_id: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    dispatched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


def create_all(engine: Engine) -> None:
    Base.metadata.create_all(engine)
