"""Tamper-evident audit ledger: an append-only, per-tenant SHA-256 hash chain.

``hash = sha256(prev_hash || JCS(record))`` where the record is
``{tenant, at, actor, action, detail}`` and ``prev_hash`` (hex) is the concatenation prefix.
``seq`` is the database-assigned autoincrement key; it is *not* hashed, because order is bound
by the prev_hash linkage (swapping rows breaks the chain) and seq is unknown before insert.
The first record of a tenant chains to GENESIS_HASH. Rows are never updated or deleted by this
module. Document content must never enter ``detail``: keys that look like content are refused
and long strings are rejected.

Truncating the *tail* of a chain is not detectable from the chain alone; export ``head()``
periodically to an external anchor (WORM store, signed log) to cover that.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import AuditLog, lock_tenant
from .exceptions import CanonicalizationError, InvalidDetail
from .models import AuthorizeRequest, AuthorizeResponse
from .signing import canonicalize

GENESIS_HASH = "0" * 64
MAX_STRING = 512
#: Detail keys that would indicate document/prompt content leaking into the ledger.
FORBIDDEN_KEYS = frozenset(
    {"content", "text", "body", "document", "prompt", "completion", "payload", "chunk", "snippet", "data"}
)


def _utc(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.now(UTC)
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _stamp(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _check_detail(value: Any, path: str = "detail") -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise InvalidDetail(f"{path}: keys must be strings")
            if k.lower() in FORBIDDEN_KEYS:
                raise InvalidDetail(f"{path}.{k}: content-like keys are not allowed in the audit ledger")
            _check_detail(v, f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _check_detail(v, f"{path}[{i}]")
    elif isinstance(value, str):
        if len(value) > MAX_STRING:
            raise InvalidDetail(f"{path}: string longer than {MAX_STRING} chars (content must not enter the ledger)")
    elif value is None or isinstance(value, (bool, int, float)):
        pass
    else:
        raise InvalidDetail(f"{path}: unsupported type {type(value).__name__}")


def compute_hash(prev_hash: str, tenant_id: str, at: datetime, actor: str, action: str, detail: dict) -> str:
    record = {
        "tenant": tenant_id,
        "at": _stamp(at),
        "actor": actor,
        "action": action,
        "detail": detail,
    }
    return hashlib.sha256(prev_hash.encode("ascii") + canonicalize(record)).hexdigest()


def append(
    session: Session,
    tenant: str,
    actor: str,
    action: str,
    detail: dict[str, Any] | None = None,
    *,
    at: datetime | None = None,
) -> AuditLog:
    """Append one record to the tenant's chain inside the caller's transaction (no commit).

    Appenders on the same tenant are serialised by a row lock on the tenant (Postgres) or the database
    write lock (SQLite), see :func:`ales_core.db.lock_tenant`; the unique (tenant_id, prev_hash) constraint is the backstop that turns any residual race into
    an IntegrityError instead of a forked chain.
    """
    if not tenant or not actor or not action:
        raise InvalidDetail("tenant, actor and action are required")
    detail = dict(detail or {})
    _check_detail(detail)
    try:
        canonicalize(detail)
    except CanonicalizationError as exc:
        raise InvalidDetail(f"detail is not canonicalisable: {exc}") from exc
    when = _utc(at)

    lock_tenant(session, tenant)  # creates the tenant if needed and serialises appenders on it
    last = session.execute(
        select(AuditLog.hash).where(AuditLog.tenant_id == tenant).order_by(AuditLog.seq.desc()).limit(1)
    ).scalar_one_or_none()
    prev = last or GENESIS_HASH
    row = AuditLog(
        tenant_id=tenant,
        prev_hash=prev,
        hash=compute_hash(prev, tenant, when, actor, action, detail),
        at=when,
        actor=actor,
        action=action,
        detail=detail,
    )
    session.add(row)
    session.flush()
    return row


def record_decision(
    session: Session,
    actor: str,
    request: AuthorizeRequest,
    response: AuthorizeResponse,
    *,
    at: datetime | None = None,
    extra: dict[str, Any] | None = None,
) -> AuditLog:
    """Ledger entry for one authorize decision. Identifiers and verdicts only, never content.

    ``actor`` must be the *authenticated* caller (token subject), not a request field.
    """
    detail = {
        "trace_id": response.trace_id,
        "principal": {"type": request.principal.type, "id": request.principal.id},
        "purpose": request.purpose,
        "agent_id": request.agent_id,
        "session_id": request.session_id,
        "decision": response.decision.value,
        "reason": [r.value for r in response.reason],
        "revocation_epoch": response.revocation_epoch,
        "policy_version": response.policy_version,
        "objects": [
            {
                "context_id": o.context_id,
                "version": o.version,
                "decision": o.decision.value,
                "reason": [r.value for r in o.reason],
            }
            for o in response.objects
        ],
    }
    if request.tools:
        detail["tools"] = list(request.tools)
    if request.risk is not None:
        detail["risk"] = request.risk
    if extra:
        detail["policy"] = dict(extra)  # identifiers only: policy_rule_id, approval_id, fingerprint
    return append(session, request.tenant_id, actor, "decision.authorize", detail, at=at)


def head(session: Session, tenant: str) -> tuple[int, str] | None:
    """(seq, hash) of the newest record of a tenant chain, for external anchoring."""
    row = session.execute(
        select(AuditLog.seq, AuditLog.hash).where(AuditLog.tenant_id == tenant).order_by(AuditLog.seq.desc()).limit(1)
    ).first()
    return (row[0], row[1]) if row else None


def verify_chain(session: Session, tenant: str | None = None) -> tuple[bool, int | None]:
    """Recompute every hash; return ``(ok, first_bad_seq)``.

    ``tenant=None`` verifies every tenant's chain and reports the lowest bad seq. A deleted
    middle record, an edited field, a reordered row or a forged hash all surface as the first
    seq whose recomputed hash or predecessor link does not match.
    """
    stmt = select(AuditLog).order_by(AuditLog.seq)
    if tenant is not None:
        stmt = stmt.where(AuditLog.tenant_id == tenant)
    prev_by_tenant: dict[str, str] = {}
    bad: int | None = None
    for row in session.scalars(stmt):
        expected_prev = prev_by_tenant.get(row.tenant_id, GENESIS_HASH)
        ok = row.prev_hash == expected_prev
        if ok:
            try:
                ok = row.hash == compute_hash(
                    row.prev_hash, row.tenant_id, row.at, row.actor, row.action, row.detail
                )
            except (CanonicalizationError, TypeError, ValueError):
                ok = False
        if not ok:
            bad = row.seq if bad is None else min(bad, row.seq)
            # keep walking other tenants; within this tenant continue from the stored hash so
            # a single bad row does not mask a later one, but the first is what we report.
        prev_by_tenant[row.tenant_id] = row.hash
    return (bad is None, bad)
