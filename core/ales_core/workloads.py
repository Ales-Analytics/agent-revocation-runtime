"""Workload identity and delegation (spec v0.3).

Agents, tools, connectors and services are first-class identities. Everything here fails closed:
an unknown workload behaves exactly like a suspended one.

Adoption gate
-------------
Workload enforcement in the resolver is **opt-in per tenant**: it activates only once the tenant has
registered at least one workload (:meth:`WorkloadRegistry.has_any`). A tenant with no workloads keeps
the pre-v0.3 behaviour (``agent_id`` is an unverified label). Once a tenant has any workload, an
``agent_id`` that is unknown or suspended is denied (``WORKLOAD_SUSPENDED``), and any requested tool
must be one of the agent's capabilities (``CAPABILITY_MISSING``).

Capability matching: a tool name ``t`` is permitted when the workload's capabilities contain ``t``
or ``"tool:" + t`` exactly (no wildcards).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit
from .db import DelegationRow, WorkloadGrantRow, WorkloadRow, lock_tenant, utcnow
from .exceptions import AlesError
from .models import Decision, ReasonCode
from .tombstones import utc


class WorkloadError(AlesError):
    """Invalid workload/delegation operation (duplicate, unknown workload, bad argument)."""


class WorkloadKind(StrEnum):
    AGENT = "agent"
    TOOL = "tool"
    CONNECTOR = "connector"
    SERVICE = "service"


class WorkloadStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


DelegationCheck = Literal["ok", "missing", "expired", "revoked"]


def _norm_caps(caps: list[str] | None) -> list[str]:
    out = sorted({c for c in (caps or [])})
    if any((not isinstance(c, str)) or not c.strip() for c in out):
        raise WorkloadError("capabilities must be non-empty strings")
    return out


class WorkloadRegistry:
    @staticmethod
    def register(
        session: Session,
        tenant: str,
        workload_id: str,
        kind: WorkloadKind | str,
        display_name: str,
        capabilities: list[str] | None = None,
        *,
        actor: str,
        at: datetime | None = None,
    ) -> WorkloadRow:
        if not workload_id:
            raise WorkloadError("workload_id required")
        kind_v = WorkloadKind(kind).value  # ValueError on unknown kind
        caps = _norm_caps(capabilities)
        lock_tenant(session, tenant)
        if WorkloadRegistry.get(session, tenant, workload_id) is not None:
            raise WorkloadError(f"workload {workload_id!r} already registered")
        row = WorkloadRow(
            tenant_id=tenant,
            workload_id=workload_id,
            kind=kind_v,
            display_name=display_name,
            capabilities=caps,
            status=WorkloadStatus.ACTIVE.value,
            created_at=utc(at) if at else utcnow(),
        )
        session.add(row)
        session.flush()
        audit.append(
            session, tenant, actor, "workload.register",
            {"workload_id": workload_id, "kind": kind_v, "capabilities": caps}, at=at,
        )
        return row

    @staticmethod
    def get(session: Session, tenant: str, workload_id: str) -> WorkloadRow | None:
        return session.scalars(
            select(WorkloadRow).where(WorkloadRow.tenant_id == tenant, WorkloadRow.workload_id == workload_id)
        ).first()

    @staticmethod
    def list_all(session: Session, tenant: str) -> list[WorkloadRow]:
        return list(
            session.scalars(select(WorkloadRow).where(WorkloadRow.tenant_id == tenant).order_by(WorkloadRow.workload_id))
        )

    @staticmethod
    def has_any(session: Session, tenant: str) -> bool:
        return (
            session.scalar(select(func.count()).select_from(WorkloadRow).where(WorkloadRow.tenant_id == tenant)) or 0
        ) > 0

    @staticmethod
    def set_status(
        session: Session, tenant: str, workload_id: str, status: WorkloadStatus | str, *,
        actor: str, at: datetime | None = None,
    ) -> WorkloadRow:
        status_v = WorkloadStatus(status).value
        lock_tenant(session, tenant)
        row = WorkloadRegistry.get(session, tenant, workload_id)
        if row is None:
            raise WorkloadError(f"workload {workload_id!r} not registered")
        previous = row.status
        row.status = status_v
        session.flush()
        audit.append(
            session, tenant, actor, "workload.status",
            {"workload_id": workload_id, "status": status_v, "previous": previous}, at=at,
        )
        return row

    @staticmethod
    def set_capabilities(
        session: Session, tenant: str, workload_id: str, capabilities: list[str], *,
        actor: str, at: datetime | None = None,
    ) -> WorkloadRow:
        caps = _norm_caps(capabilities)
        lock_tenant(session, tenant)
        row = WorkloadRegistry.get(session, tenant, workload_id)
        if row is None:
            raise WorkloadError(f"workload {workload_id!r} not registered")
        row.capabilities = caps
        session.flush()
        audit.append(
            session, tenant, actor, "workload.capabilities", {"workload_id": workload_id, "capabilities": caps}, at=at
        )
        return row

    # -- grants: which principals may act as which workload --------------------------------

    @staticmethod
    def grant(
        session: Session, tenant: str, principal_id: str, workload_id: str, *, actor: str, at: datetime | None = None
    ) -> WorkloadGrantRow:
        lock_tenant(session, tenant)
        if WorkloadRegistry.get(session, tenant, workload_id) is None:
            raise WorkloadError(f"workload {workload_id!r} not registered")
        existing = session.scalars(
            select(WorkloadGrantRow).where(
                WorkloadGrantRow.tenant_id == tenant,
                WorkloadGrantRow.principal_id == principal_id,
                WorkloadGrantRow.workload_id == workload_id,
            )
        ).first()
        if existing is not None:
            return existing  # idempotent
        row = WorkloadGrantRow(
            tenant_id=tenant, principal_id=principal_id, workload_id=workload_id, granted_by=actor,
            created_at=utc(at) if at else utcnow(),
        )
        session.add(row)
        session.flush()
        audit.append(
            session, tenant, actor, "workload.grant", {"principal_id": principal_id, "workload_id": workload_id}, at=at
        )
        return row

    @staticmethod
    def revoke_grant(
        session: Session, tenant: str, principal_id: str, workload_id: str, *, actor: str, at: datetime | None = None
    ) -> bool:
        lock_tenant(session, tenant)
        row = session.scalars(
            select(WorkloadGrantRow).where(
                WorkloadGrantRow.tenant_id == tenant,
                WorkloadGrantRow.principal_id == principal_id,
                WorkloadGrantRow.workload_id == workload_id,
            )
        ).first()
        if row is None:
            return False
        session.delete(row)
        session.flush()
        audit.append(
            session, tenant, actor, "workload.grant_revoke",
            {"principal_id": principal_id, "workload_id": workload_id}, at=at,
        )
        return True

    @staticmethod
    def list_grants(session: Session, tenant: str, principal_id: str | None = None) -> list[WorkloadGrantRow]:
        stmt = select(WorkloadGrantRow).where(WorkloadGrantRow.tenant_id == tenant)
        if principal_id is not None:
            stmt = stmt.where(WorkloadGrantRow.principal_id == principal_id)
        return list(session.scalars(stmt.order_by(WorkloadGrantRow.id)))

    @staticmethod
    def can_act_as(session: Session, tenant: str, principal_id: str, workload_id: str) -> bool:
        """True only with an explicit grant AND an active workload (suspended/unknown = False)."""
        if not is_active(session, tenant, workload_id):
            return False
        return (
            session.scalars(
                select(WorkloadGrantRow.id).where(
                    WorkloadGrantRow.tenant_id == tenant,
                    WorkloadGrantRow.principal_id == principal_id,
                    WorkloadGrantRow.workload_id == workload_id,
                )
            ).first()
            is not None
        )


def is_active(session: Session, tenant: str, workload_id: str) -> bool:
    row = WorkloadRegistry.get(session, tenant, workload_id)
    return row is not None and row.status == WorkloadStatus.ACTIVE.value


def has_capability(caps: list[str], tool: str) -> bool:
    return tool in caps or f"tool:{tool}" in caps


def check_capability(session: Session, tenant: str, workload_id: str, capability: str) -> bool:
    """True iff the workload exists, is active and holds ``capability`` (exact, or ``tool:``-prefixed)."""
    row = WorkloadRegistry.get(session, tenant, workload_id)
    if row is None or row.status != WorkloadStatus.ACTIVE.value:
        return False
    return has_capability(list(row.capabilities or []), capability)


class DelegationStore:
    @staticmethod
    def create(
        session: Session,
        tenant: str,
        from_workload: str,
        to_workload: str,
        *,
        purposes: list[str] | None = None,
        expires_at: datetime | None = None,
        actor: str,
        at: datetime | None = None,
        delegation_id: str | None = None,
    ) -> DelegationRow:
        if purposes is not None and (not purposes or any((not isinstance(p, str)) or not p for p in purposes)):
            raise WorkloadError("purposes must be omitted (all purposes) or a non-empty list of strings")
        lock_tenant(session, tenant)
        for w in (from_workload, to_workload):
            if WorkloadRegistry.get(session, tenant, w) is None:
                raise WorkloadError(f"workload {w!r} not registered")
        row = DelegationRow(
            delegation_id=delegation_id or str(uuid.uuid4()),
            tenant_id=tenant,
            from_workload=from_workload,
            to_workload=to_workload,
            purposes=sorted(set(purposes)) if purposes is not None else None,
            expires_at=utc(expires_at) if expires_at else None,
            status="active",
            created_at=utc(at) if at else utcnow(),
        )
        session.add(row)
        session.flush()
        audit.append(
            session, tenant, actor, "delegation.create",
            {
                "delegation_id": row.delegation_id,
                "from_workload": from_workload,
                "to_workload": to_workload,
                "purposes": row.purposes,
                "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            },
            at=at,
        )
        return row

    @staticmethod
    def revoke(
        session: Session, tenant: str, delegation_id: str, *, actor: str, at: datetime | None = None
    ) -> DelegationRow:
        lock_tenant(session, tenant)
        row = session.scalars(
            select(DelegationRow).where(DelegationRow.tenant_id == tenant, DelegationRow.delegation_id == delegation_id)
        ).first()
        if row is None:
            raise WorkloadError(f"delegation {delegation_id!r} not found")
        row.status = "revoked"  # idempotent
        session.flush()
        audit.append(
            session, tenant, actor, "delegation.revoke",
            {"delegation_id": delegation_id, "from_workload": row.from_workload, "to_workload": row.to_workload},
            at=at,
        )
        return row

    @staticmethod
    def list_all(
        session: Session, tenant: str, *, from_workload: str | None = None, to_workload: str | None = None
    ) -> list[DelegationRow]:
        stmt = select(DelegationRow).where(DelegationRow.tenant_id == tenant)
        if from_workload is not None:
            stmt = stmt.where(DelegationRow.from_workload == from_workload)
        if to_workload is not None:
            stmt = stmt.where(DelegationRow.to_workload == to_workload)
        return list(session.scalars(stmt.order_by(DelegationRow.created_at, DelegationRow.delegation_id)))

    @staticmethod
    def check(
        session: Session, tenant: str, from_w: str, to_w: str, purpose: str, now: datetime
    ) -> DelegationCheck:
        """``ok`` iff some active, unexpired delegation from_w -> to_w covers ``purpose`` (``purposes``
        NULL = all purposes). Otherwise the most informative failure among purpose-matching rows:
        ``expired`` (active but ``expires_at <= now``) > ``revoked`` > ``missing``. Pure read."""
        now = utc(now)
        rows = session.scalars(
            select(DelegationRow).where(
                DelegationRow.tenant_id == tenant,
                DelegationRow.from_workload == from_w,
                DelegationRow.to_workload == to_w,
            )
        ).all()
        expired = revoked = False
        for d in rows:
            if d.purposes is not None and purpose not in d.purposes:
                continue
            if d.status != "active":
                revoked = True
            elif d.expires_at is not None and utc(d.expires_at) <= now:
                expired = True
            else:
                return "ok"
        if expired:
            return "expired"
        if revoked:
            return "revoked"
        return "missing"


def authorize_handoff(
    session: Session, tenant: str, from_workload: str, to_workload: str, purpose: str, now: datetime
) -> tuple[Decision, list[ReasonCode]]:
    """Authorize an agent-to-agent handoff. DENY + ``WORKLOAD_SUSPENDED`` if either side is suspended
    or unknown; DENY + ``DELEGATION_MISSING`` if no valid delegation (missing, expired or revoked);
    both reasons are reported when both apply. ALLOW + ``[OK]`` otherwise."""
    reasons: list[ReasonCode] = []
    if not (is_active(session, tenant, from_workload) and is_active(session, tenant, to_workload)):
        reasons.append(ReasonCode.WORKLOAD_SUSPENDED)
    if DelegationStore.check(session, tenant, from_workload, to_workload, purpose, now) != "ok":
        reasons.append(ReasonCode.DELEGATION_MISSING)
    if reasons:
        return Decision.DENY, reasons
    return Decision.ALLOW, [ReasonCode.OK]
