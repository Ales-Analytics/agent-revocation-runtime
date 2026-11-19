"""Tombstone helpers shared by the revocation engine, graph registration and the resolver.

Semantics (normative for core, see SPEC "Scoped and delayed revocation"):

* A tombstone *applies* to a request at time ``now`` iff ``now >= effective_at`` AND its scope
  matches the request principal AND purpose. A scope list that is empty/absent matches
  everything on that axis, so a scope with both axes empty is an unscoped (full) revocation.
* Several scoped tombstones union as sets of (principal, purpose) pairs: a request is denied if
  ANY single tombstone matches it. Scopes of different tombstones are never cross-multiplied.
* Any applying unscoped tombstone denies everyone; scoping can only narrow what one event
  denies, never grant access another event removed.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from . import audit
from .db import ContextObject, InvalidationOutbox, Tombstone
from .models import AffectedScope

# Deterministic tie-break when several reasons cover one object (informational flag only).
REASON_RANK = {
    "deleted": 6,
    "acl_changed": 5,
    "compromised": 4,
    "poisoned": 4,
    "expired": 3,
    "version_superseded": 2,
}


def utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def normalize_scope(scope: AffectedScope | None) -> tuple[list[str] | None, list[str] | None]:
    """Canonical stored form: sorted unique lists, ``None`` for an empty/absent axis."""
    if scope is None:
        return None, None
    principals = sorted(set(scope.principals or [])) or None
    purposes = sorted(set(scope.purposes or [])) or None
    return principals, purposes


def covers_node(t: Tombstone, context_id: str, version: str) -> bool:
    return t.context_id == context_id and (t.object_version is None or t.object_version == version)


def applies(t: Tombstone, principal_id: str, purpose: str, now: datetime) -> bool:
    if utc(now) < utc(t.effective_at):
        return False
    if t.scope_principals and principal_id not in t.scope_principals:
        return False
    return not (t.scope_purposes and purpose not in t.scope_purposes)


def load_tombstones(session: Session, tenant_id: str, context_ids: set[str]) -> list[Tombstone]:
    """All tombstones of a tenant for the given context ids, in a deterministic order."""
    if not context_ids:
        return []
    statement = select(Tombstone).where(
        Tombstone.tenant_id == tenant_id, Tombstone.context_id.in_(context_ids)
    )
    rows = list(session.scalars(statement))
    rows.sort(key=lambda t: (utc(t.effective_at), t.event_id, t.id or 0))
    return rows


def enqueue_outbox(
    session: Session,
    row: ContextObject,
    reason: str,
    event_id: str | None,
    available_at: datetime,
) -> InvalidationOutbox:
    ob = InvalidationOutbox(
        tenant_id=row.tenant_id,
        context_id=row.context_id,
        version=row.object_version,
        reason=reason,
        dispatched=False,
        store_kind=row.kind,
        event_id=event_id,
        state="pending",
        attempts=0,
        available_at=available_at,
    )
    session.add(ob)
    return ob


def mark_flag(row: ContextObject, reason: str) -> None:
    """Set the informational ``tombstoned`` flag; the reason is the highest-ranked, order-independent."""
    if not row.tombstoned or REASON_RANK.get(reason, 0) > REASON_RANK.get(row.tombstone_reason or "", 0):
        row.tombstone_reason = reason
    row.tombstoned = True


def materialize_pending(session: Session, row: ContextObject, now: datetime | None = None) -> bool:
    """Apply tombstones that were accepted before ``row`` existed (retroactive revocation).

    Called for every newly inserted object. Denial itself never depends on this (the resolver
    reads the tombstone table), but purge scheduling and the lineage flag do. Scoped tombstones
    schedule no purge: purge is global and would remove data other principals may still use.
    Returns True if any tombstone matched.
    """
    statement = select(Tombstone).where(
        Tombstone.tenant_id == row.tenant_id,
        Tombstone.context_id == row.context_id,
        or_(Tombstone.object_version.is_(None), Tombstone.object_version == row.object_version),
    )
    matches = sorted(session.scalars(statement), key=lambda t: (utc(t.effective_at), t.event_id, t.id or 0))
    if not matches:
        return False
    when = utc(now) if now else datetime.now(UTC)
    unscoped = [t for t in matches if not t.scoped]
    if unscoped:
        for t in unscoped:
            if utc(t.effective_at) <= when:
                mark_flag(row, t.reason)
        first = unscoped[0]
        enqueue_outbox(session, row, first.reason, first.event_id, utc(first.effective_at))
    audit.append(
        session,
        row.tenant_id,
        "system",
        "revocation.apply_pending",
        {
            "context_id": row.context_id,
            "version": row.object_version,
            "event_ids": [t.event_id for t in matches],
            "scoped_only": not unscoped,
        },
        at=when,
    )
    return True


def is_tombstoned(session: Session, tenant_id: str, context_id: str, version: str, now: datetime) -> bool:
    """True if an applying *unscoped* tombstone covers the object or any ancestor at ``now``.

    Use this (not the informational ``ContextObject.tombstoned`` column) when a caller needs the
    time-correct answer, e.g. a lineage inspection endpoint.
    """
    from .graph import GraphStore  # local import: graph imports this module

    nodes = [(context_id, version)] + GraphStore(session).get_ancestors(tenant_id, context_id, version)
    ts = load_tombstones(session, tenant_id, {n[0] for n in nodes})
    return any(
        not t.scoped and applies(t, "", "", now) and any(covers_node(t, c, v) for c, v in nodes) for t in ts
    )
