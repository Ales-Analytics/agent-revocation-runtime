"""Human-review approvals (spec v0.3).

An approval authorises only requests whose *fingerprint* equals the approved one, until
``expires_at``. The resolver only ever **reads** approvals (:meth:`ApprovalStore.lookup`); creating the
pending record is the server layer's job (:meth:`ApprovalStore.ensure_pending`) so that the decision
path stays read-only.

State machine: ``pending -> approved | denied`` (via :meth:`decide`, audited). ``approved`` and
``denied`` both carry ``expires_at = decided_at + ttl``; once past it the record is *effectively
expired* (``status`` reports ``none``) and the next identical request creates a fresh pending record.
The stored ``state`` is only rewritten to ``expired`` by :meth:`mark_expired` (housekeeping); reads never
depend on it.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .db import ApprovalRow, lock_tenant, utcnow
from .exceptions import AlesError
from .models import ObjectRef, Principal
from .signing import canonicalize
from .tombstones import utc

ApprovalStatus = Literal["none", "pending", "approved", "denied"]


class ApprovalError(AlesError):
    """Unknown approval, or a decision on a record that is not pending."""


class SeparationOfDuties(ApprovalError):
    """The decider is the requester (the principal whose access is pending, or the authenticated actor
    whose ``/v1/authorize`` call created the request)."""

    MESSAGE = "separation of duties: decider matches requester"

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


def fingerprint(
    principal: Principal | dict[str, Any] | str,
    purpose: str,
    objects: Iterable[tuple[str, str | None] | ObjectRef | dict[str, Any]],
    tools: Iterable[str] | None,
    risk: str | None,
    policy_version: str,
) -> str:
    """sha256 hex over the RFC 8785 canonical form of
    ``(principal, purpose, object set, tools, risk, policy_version)``.

    ``tools`` is sorted and de-duplicated; ``risk`` is the caller-asserted tier or ``None``. Both are
    bound so an approval for one tool / risk level never covers another.

    The object set is order- and duplicate-insensitive. Pass the *resolved* version of each object so
    an approval is pinned to exact versions. ``principal`` may be a :class:`Principal`, a
    ``{"type", "id"}`` dict, or a bare id (type then defaults to ``"user"``).
    """
    if isinstance(principal, Principal):
        p = {"type": principal.type, "id": principal.id}
    elif isinstance(principal, dict):
        p = {"type": principal.get("type", "user"), "id": principal["id"]}
    else:
        p = {"type": "user", "id": principal}
    objs: set[tuple[str, str | None]] = set()
    for o in objects:
        if isinstance(o, ObjectRef):
            objs.add((o.context_id, o.version))
        elif isinstance(o, dict):
            objs.add((o["context_id"], o.get("version")))
        else:
            objs.add((o[0], o[1]))
    doc = {
        "principal": p,
        "purpose": purpose,
        "objects": [{"context_id": c, "version": v} for c, v in sorted(objs, key=lambda t: (t[0], t[1] or ""))],
        "tools": sorted(set(tools or ())),
        "risk": risk,
        "policy_version": policy_version,
    }
    return hashlib.sha256(canonicalize(doc)).hexdigest()


def _effective_state(row: ApprovalRow, now: datetime) -> ApprovalStatus:
    if row.state == "pending":
        return "pending"
    if row.state in ("approved", "denied"):
        if row.expires_at is None or utc(row.expires_at) <= now:
            return "none"  # fail closed: an undated or lapsed decision grants/blocks nothing
        return row.state  # type: ignore[return-value]
    return "none"  # expired (or any unknown state)


class ApprovalStore:
    @staticmethod
    def _latest(session: Session, tenant: str, fp: str) -> ApprovalRow | None:
        return session.scalars(
            select(ApprovalRow)
            .where(ApprovalRow.tenant_id == tenant, ApprovalRow.fingerprint == fp)
            .order_by(ApprovalRow.seq.desc())
            .limit(1)
        ).first()

    @staticmethod
    def lookup(session: Session, tenant: str, fp: str, now: datetime) -> tuple[ApprovalStatus, ApprovalRow | None]:
        """Read-only: ``(status, newest_record)``; the record is None when status is ``none`` and no
        record exists, and may be a lapsed record when status is ``none``."""
        row = ApprovalStore._latest(session, tenant, fp)
        if row is None:
            return "none", None
        return _effective_state(row, utc(now)), row

    @staticmethod
    def status(session: Session, tenant: str, fp: str, now: datetime) -> ApprovalStatus:
        return ApprovalStore.lookup(session, tenant, fp, now)[0]

    @staticmethod
    def ensure_pending(
        session: Session,
        tenant: str,
        fp: str,
        context: dict[str, Any],
        *,
        actor: str = "system",
        requested_by_principal: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRow:
        """Idempotent: return the live record for ``fp`` (pending, or decided and unexpired), creating a
        pending one only when none exists. ``context`` must hold identifiers only (the audit ledger and
        approvals table never store document content).

        Two identities are recorded for separation of duties: ``requested_by_principal`` (whose access is
        pending; defaults to ``context["principal"]["id"]``) and ``requested_actor`` (= ``actor``, the
        authenticated subject that made the request)."""
        if requested_by_principal is None:
            p = context.get("principal")
            if isinstance(p, dict) and isinstance(p.get("id"), str):
                requested_by_principal = p["id"]
        when = utc(now) if now else utcnow()
        lock_tenant(session, tenant)
        row = ApprovalStore._latest(session, tenant, fp)
        if row is not None and _effective_state(row, when) != "none":
            return row
        row = ApprovalRow(
            approval_id=str(uuid.uuid4()),
            tenant_id=tenant,
            fingerprint=fp,
            decision_context=context,
            state="pending",
            created_at=when,
            requested_by_principal=requested_by_principal,
            requested_actor=actor,
        )
        session.add(row)
        session.flush()
        audit.append(
            session, tenant, actor, "approval.request",
            {"approval_id": row.approval_id, "fingerprint": fp}, at=when,
        )
        return row

    @staticmethod
    def get(session: Session, tenant: str, approval_id: str) -> ApprovalRow | None:
        return session.scalars(
            select(ApprovalRow).where(ApprovalRow.tenant_id == tenant, ApprovalRow.approval_id == approval_id)
        ).first()

    @staticmethod
    def list_pending(session: Session, tenant: str) -> list[ApprovalRow]:
        return list(
            session.scalars(
                select(ApprovalRow)
                .where(ApprovalRow.tenant_id == tenant, ApprovalRow.state == "pending")
                .order_by(ApprovalRow.seq)
            )
        )

    @staticmethod
    def decide(
        session: Session,
        tenant: str,
        approval_id: str,
        approve: bool,
        decided_by: str,
        ttl_seconds: int,
        *,
        now: datetime | None = None,
        allow_self: bool = False,
    ) -> ApprovalRow:
        """Approve or deny a pending record (audited as ``approval.decide`` by ``decided_by``).
        ``ttl_seconds`` (> 0) bounds how long the decision holds; there is no open-ended approval.

        Separation of duties: raises :class:`SeparationOfDuties` when ``decided_by`` equals the record's
        ``requested_by_principal`` or ``requested_actor`` (either decision, approve or deny), unless
        ``allow_self`` (dev / single-admin escape hatch). Records created before migration 0003 have no
        requester recorded and are not blocked."""
        if ttl_seconds <= 0:
            raise ApprovalError("ttl_seconds must be positive")
        if not decided_by:
            raise ApprovalError("decided_by required")
        when = utc(now) if now else utcnow()
        lock_tenant(session, tenant)
        row = ApprovalStore.get(session, tenant, approval_id)
        if row is None:
            raise ApprovalError(f"approval {approval_id!r} not found")
        if row.state != "pending":
            raise ApprovalError(f"approval {approval_id!r} is {row.state}, not pending")
        if not allow_self and decided_by in (row.requested_by_principal, row.requested_actor):
            raise SeparationOfDuties
        row.state = "approved" if approve else "denied"
        row.decided_by = decided_by
        row.decided_at = when
        row.expires_at = when + timedelta(seconds=ttl_seconds)
        session.flush()
        audit.append(
            session, tenant, decided_by, "approval.decide",
            {
                "approval_id": approval_id,
                "fingerprint": row.fingerprint,
                "approved": approve,
                "expires_at": row.expires_at.isoformat(),
            },
            at=when,
        )
        return row

    @staticmethod
    def mark_expired(session: Session, tenant: str, now: datetime) -> int:
        """Housekeeping: rewrite lapsed approved/denied rows to state ``expired``. Returns the count."""
        when = utc(now)
        lock_tenant(session, tenant)
        n = 0
        for row in session.scalars(
            select(ApprovalRow).where(ApprovalRow.tenant_id == tenant, ApprovalRow.state.in_(("approved", "denied")))
        ):
            if row.expires_at is not None and utc(row.expires_at) <= when:
                row.state = "expired"
                n += 1
        session.flush()
        return n
