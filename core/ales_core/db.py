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
    UniqueConstraint,
    select,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
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
    issuer_key_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Informational denormalisation only: set when an unscoped revocation that was already in
    # effect at acceptance covers this object. The resolver NEVER reads it; the `tombstones`
    # table is authoritative (it carries effective_at and scope).
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
    issuer_key_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    accepted_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    resulting_epoch: Mapped[int] = mapped_column(Integer, nullable=False)


class Tombstone(Base):
    """Authoritative revocation state, one row per (event, revoked source version).

    ``object_version`` NULL is a wildcard that only exists for an event that matched no
    registered version at acceptance (unknown source): it applies to every version registered
    later. ``scope_principals``/``scope_purposes`` NULL means "all"; both NULL = unscoped.
    The row may exist before the object does (retroactive application).
    """

    __tablename__ = "tombstones"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    context_id: Mapped[str] = mapped_column(String(64), nullable=False)
    object_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason: Mapped[str] = mapped_column(String(32), nullable=False)
    effective_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    scope_principals: Mapped[list | None] = mapped_column(JSON, nullable=True)
    scope_purposes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_tombstones_tenant_ctx", "tenant_id", "context_id"),
        UniqueConstraint("event_id", "context_id", "object_version", name="uq_tombstone_event_object"),
    )

    @property
    def scoped(self) -> bool:
        return bool(self.scope_principals) or bool(self.scope_purposes)


class InvalidationOutbox(Base):
    __tablename__ = "invalidation_outbox"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    context_id: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    # Legacy boolean, kept in step with state == "done".
    dispatched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Purge routing key: the object's kind (chunk/embedding/cache/...) at write time.
    store_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="*")
    event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    lease_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Earliest time the row may be dispatched (effective_at for delayed revocations, backoff otherwise).
    available_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    __table_args__ = (Index("ix_outbox_due", "state", "available_at"),)


class IssuerKey(Base):
    __tablename__ = "issuer_keys"
    key_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    public_key_b64: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)


class AuditLog(Base):
    """Append-only, hash-chained (per tenant) audit ledger. Never updated, never deleted."""

    __tablename__ = "audit_log"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)
    at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        # A second append on the same predecessor would fork the chain: refuse it at the DB.
        UniqueConstraint("tenant_id", "prev_hash", name="uq_audit_tenant_prev"),
        Index("ix_audit_tenant_seq", "tenant_id", "seq"),
    )


class PolicyDocumentRow(Base):
    """One installed version of a tenant policy document. At most one row per tenant is ``active``
    (enforced in code under :func:`lock_tenant`, see ``policy.PolicyStore``)."""

    __tablename__ = "policy_documents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    document: Mapped[dict] = mapped_column(JSON, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    __table_args__ = (
        UniqueConstraint("tenant_id", "policy_id", "version", name="uq_policy_version"),
        Index("ix_policy_tenant_active", "tenant_id", "active"),
    )


class WorkloadRow(Base):
    __tablename__ = "workloads"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    workload_id: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    capabilities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    __table_args__ = (UniqueConstraint("tenant_id", "workload_id", name="uq_workload"),)


class WorkloadGrantRow(Base):
    """Principal P may act as workload W (explicit grant; absent grant = may not)."""

    __tablename__ = "workload_grants"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    principal_id: Mapped[str] = mapped_column(String(255), nullable=False)
    workload_id: Mapped[str] = mapped_column(String(255), nullable=False)
    granted_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    __table_args__ = (UniqueConstraint("tenant_id", "principal_id", "workload_id", name="uq_workload_grant"),)


class DelegationRow(Base):
    __tablename__ = "delegations"
    delegation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    from_workload: Mapped[str] = mapped_column(String(255), nullable=False)
    to_workload: Mapped[str] = mapped_column(String(255), nullable=False)
    purposes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    __table_args__ = (Index("ix_delegations_pair", "tenant_id", "from_workload", "to_workload"),)


class ApprovalRow(Base):
    """Human-review approval record. ``decision_context`` holds identifiers only, never content."""

    __tablename__ = "approvals"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    approval_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    decision_context: Mapped[dict] = mapped_column(JSON, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    decided_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    __table_args__ = (Index("ix_approvals_fp", "tenant_id", "fingerprint"),)


def lock_tenant(session: Session, tenant_id: str) -> Tenant:
    """Create the tenant row if absent (race-free) and take its write lock for this transaction.

    Concurrent first writers for a new tenant used to both ``INSERT`` and one died on the primary key;
    the insert is now ``ON CONFLICT DO NOTHING``. The row lock (Postgres ``FOR UPDATE``; on SQLite the
    insert statement itself takes the database write lock) is taken BEFORE any child-row insert, so
    writers of one tenant serialise with a single, consistent lock order. Without that, two registrations
    each hold a FOR KEY SHARE lock (from the FK on their new object) and then both ask for the exclusive
    lock in ``audit.append`` -> Postgres deadlock.
    """
    name = session.get_bind().dialect.name
    if name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as _insert
    elif name == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as _insert  # type: ignore[assignment]
    else:  # pragma: no cover - other dialects: best-effort check-then-insert
        t = session.get(Tenant, tenant_id)
        if t is None:
            t = Tenant(tenant_id=tenant_id, revocation_epoch=0)
            session.add(t)
            session.flush()
        return t
    session.execute(_insert(Tenant).values(tenant_id=tenant_id, revocation_epoch=0).on_conflict_do_nothing())
    # populate_existing: the epoch/row must reflect the committed state seen after the lock is granted.
    return session.execute(
        select(Tenant).where(Tenant.tenant_id == tenant_id).with_for_update().execution_options(populate_existing=True)
    ).scalar_one()


def create_all(engine: Engine) -> None:
    Base.metadata.create_all(engine)
