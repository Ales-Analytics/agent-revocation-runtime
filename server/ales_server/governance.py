"""v0.3 governance surface: policies, workloads, delegations, handoffs, approvals, metrics.

Same conventions as ``routes.py``: every route declares its role, binds its tenant to the credential via
``bind_tenant`` and reads the acting principal only from the authenticated identity (never a body field).
The core stores take the actor as a keyword argument and never commit; each handler commits (or rolls
back) exactly once, so a mutation and its audit record are atomic.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from ales_core import (
    ApprovalError,
    ApprovalStore,
    AuditLog,
    DelegationRow,
    DelegationStore,
    PolicyDocument,
    PolicyError,
    PolicyStore,
    Tenant,
    WorkloadError,
    WorkloadGrantRow,
    WorkloadRegistry,
    WorkloadRow,
    audit_append,
    authorize_handoff,
    outbox_stats,
)
from ales_core.db import lock_tenant
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import Identity, bind_tenant, require
from .metrics import render
from .routes import AdminDep, ReadDep, SessionDep

router = APIRouter(prefix="/v1")

MAX_ID = 255
Short = Annotated[str, StringConstraints(min_length=1, max_length=MAX_ID)]
MAX_TTL_SECONDS = 30 * 24 * 3600  # an approval can never be open-ended nor longer than 30 days


def _now(request: Request) -> datetime:
    return request.app.state.clock()


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


def _policy_view(policy_id: str, version: int, active: bool, **extra: Any) -> dict[str, Any]:
    return {
        "policy_id": policy_id,
        "version": version,
        "policy_version": f"{policy_id}@{version}",
        "active": active,
        **extra,
    }


@router.post("/policies", status_code=201)
def install_policy(
    body: dict[str, Any], session: Session = SessionDep, ident: Identity = AdminDep
) -> dict[str, Any]:
    tenant = bind_tenant(ident, body.get("tenant_id"))
    data = dict(body)
    data["tenant_id"] = tenant  # forced: the credential's tenant
    data["created_by"] = ident.subject  # forced: never a body-supplied author
    data.pop("created_at", None)  # server clock
    document = PolicyDocument.model_validate(data)  # ValidationError -> 422 via the app handler
    try:
        row = PolicyStore.install(session, document)
        session.commit()
    except PolicyError as exc:
        session.rollback()
        raise HTTPException(409, detail=str(exc)[:300]) from exc
    except IntegrityError as exc:  # concurrent install of the same (policy_id, version)
        session.rollback()
        raise HTTPException(409, detail="policy version already installed") from exc
    except Exception:
        session.rollback()
        raise
    return _policy_view(
        row.policy_id, row.version, row.active, created_by=row.created_by, created_at=_iso(row.created_at)
    )


def bump_epoch_for_policy(
    session: Session, tenant: str, actor: str, detail: dict[str, Any], at: datetime
) -> int:
    """Bump the tenant revocation epoch (same transaction as the activation) so every epoch-keyed cache
    (SDK decision cache, signed snapshot) is invalidated and ALLOWs issued under the old policy are
    re-authorised. Conservative: policy change forces re-authorization. TODO: move into ales_core."""
    lock_tenant(session, tenant)
    session.execute(
        update(Tenant).where(Tenant.tenant_id == tenant).values(revocation_epoch=Tenant.revocation_epoch + 1)
    )
    epoch = int(
        session.execute(select(Tenant.revocation_epoch).where(Tenant.tenant_id == tenant)).scalar_one()
    )
    audit_append(session, tenant, actor, "policy.epoch_bump", {**detail, "revocation_epoch": epoch}, at=at)
    return epoch


@router.post("/policies/{policy_id}/versions/{version}/activate")
def activate_policy(
    request: Request, policy_id: str, version: int, session: Session = SessionDep, ident: Identity = AdminDep
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    try:
        now = _now(request)
        row = PolicyStore.activate(session, tenant, policy_id, version, actor=ident.subject, at=now)
        bump_epoch_for_policy(
            session, tenant, ident.subject, {"policy_id": policy_id, "version": version}, now
        )
        session.commit()
    except PolicyError as exc:
        session.rollback()
        raise HTTPException(404, detail=str(exc)[:300]) from exc
    except Exception:
        session.rollback()
        raise
    return _policy_view(row.policy_id, row.version, row.active)


@router.get("/policies")
def list_policies(
    policy_id: str | None = Query(default=None), session: Session = SessionDep, ident: Identity = AdminDep
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    return {
        "policies": [
            _policy_view(p, v, a) for p, v, a in PolicyStore.list_versions(session, tenant, policy_id)
        ]
    }


@router.get("/policies/{policy_id}/versions/{version}")
def get_policy(
    policy_id: str, version: int, session: Session = SessionDep, ident: Identity = AdminDep
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    document = PolicyStore.get(session, tenant, policy_id, version)
    if document is None:
        raise HTTPException(404, detail="unknown policy version")
    active = any(a for p, v, a in PolicyStore.list_versions(session, tenant, policy_id) if v == version)
    return _policy_view(policy_id, version, active, document=document.model_dump(mode="json"))


class WorkloadCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workload_id: str = Field(min_length=1, max_length=MAX_ID)
    kind: Literal["agent", "tool", "connector", "service"]
    display_name: str = Field(min_length=1, max_length=MAX_ID)
    capabilities: list[Short] = Field(default_factory=list, max_length=256)


class WorkloadPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["active", "suspended"] | None = None
    capabilities: list[Short] | None = Field(default=None, max_length=256)


def _workload_view(row: WorkloadRow) -> dict[str, Any]:
    return {
        "workload_id": row.workload_id,
        "kind": row.kind,
        "display_name": row.display_name,
        "capabilities": list(row.capabilities or []),
        "status": row.status,
        "created_at": _iso(row.created_at),
    }


@router.post("/workloads", status_code=201)
def create_workload(
    request: Request, body: WorkloadCreate, session: Session = SessionDep, ident: Identity = AdminDep
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    try:
        row = WorkloadRegistry.register(
            session,
            tenant,
            body.workload_id,
            body.kind,
            body.display_name,
            body.capabilities,
            actor=ident.subject,
            at=_now(request),
        )
        session.commit()
    except WorkloadError as exc:
        session.rollback()
        raise HTTPException(409 if "already registered" in str(exc) else 422, detail=str(exc)[:300]) from exc
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(409, detail="workload already registered") from exc
    except Exception:
        session.rollback()
        raise
    return _workload_view(row)


@router.patch("/workloads/{workload_id}")
def patch_workload(
    request: Request,
    workload_id: str,
    body: WorkloadPatch,
    session: Session = SessionDep,
    ident: Identity = AdminDep,
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    if body.status is None and body.capabilities is None:
        raise HTTPException(422, detail="status or capabilities required")
    if WorkloadRegistry.get(session, tenant, workload_id) is None:
        raise HTTPException(404, detail="unknown workload")
    at = _now(request)
    try:
        row: WorkloadRow | None = None
        if body.status is not None:
            row = WorkloadRegistry.set_status(
                session, tenant, workload_id, body.status, actor=ident.subject, at=at
            )
        if body.capabilities is not None:
            row = WorkloadRegistry.set_capabilities(
                session, tenant, workload_id, body.capabilities, actor=ident.subject, at=at
            )
        session.commit()
    except WorkloadError as exc:
        session.rollback()
        raise HTTPException(422, detail=str(exc)[:300]) from exc
    except Exception:
        session.rollback()
        raise
    assert row is not None
    return _workload_view(row)


@router.get("/workloads")
def list_workloads(session: Session = SessionDep, ident: Identity = ReadDep) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    return {"workloads": [_workload_view(r) for r in WorkloadRegistry.list_all(session, tenant)]}


class GrantCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principal_id: str = Field(min_length=1, max_length=MAX_ID)


def _grant_view(row: WorkloadGrantRow) -> dict[str, Any]:
    return {
        "principal_id": row.principal_id,
        "workload_id": row.workload_id,
        "granted_by": row.granted_by,
        "created_at": _iso(row.created_at),
    }


@router.post("/workloads/{workload_id}/grants", status_code=201)
def create_grant(
    request: Request,
    workload_id: str,
    body: GrantCreate,
    session: Session = SessionDep,
    ident: Identity = AdminDep,
) -> dict[str, Any]:
    """Let ``principal_id`` act as the workload. Idempotent. Once a tenant has any grant, the resolver
    requires one for every request that names an agent workload (see ``ales_core.workloads``)."""
    tenant = bind_tenant(ident)
    if WorkloadRegistry.get(session, tenant, workload_id) is None:
        raise HTTPException(404, detail="unknown workload")
    try:
        row = WorkloadRegistry.grant(
            session, tenant, body.principal_id, workload_id, actor=ident.subject, at=_now(request)
        )
        session.commit()
    except WorkloadError as exc:
        session.rollback()
        raise HTTPException(404, detail=str(exc)[:300]) from exc
    except IntegrityError:  # a concurrent identical grant won: same end state
        session.rollback()
        existing = [
            g
            for g in WorkloadRegistry.list_grants(session, tenant, body.principal_id)
            if g.workload_id == workload_id
        ]
        if not existing:
            raise
        row = existing[0]
    except Exception:
        session.rollback()
        raise
    return _grant_view(row)


@router.delete("/workloads/{workload_id}/grants/{principal_id:path}")
def revoke_grant(
    request: Request,
    workload_id: str,
    principal_id: str,
    session: Session = SessionDep,
    ident: Identity = AdminDep,
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    try:
        removed = WorkloadRegistry.revoke_grant(
            session, tenant, principal_id, workload_id, actor=ident.subject, at=_now(request)
        )
        session.commit()
    except Exception:
        session.rollback()
        raise
    if not removed:  # other tenants' grants are indistinguishable from absent
        raise HTTPException(404, detail="unknown grant")
    return {"principal_id": principal_id, "workload_id": workload_id, "revoked": True}


@router.get("/grants")
def list_grants(
    principal_id: str | None = Query(default=None), session: Session = SessionDep, ident: Identity = ReadDep
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    return {"grants": [_grant_view(r) for r in WorkloadRegistry.list_grants(session, tenant, principal_id)]}


class DelegationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    from_workload: str = Field(min_length=1, max_length=MAX_ID)
    to_workload: str = Field(min_length=1, max_length=MAX_ID)
    purposes: list[Short] | None = Field(default=None, min_length=1, max_length=64)
    expires_at: AwareDatetime | None = None


def _delegation_view(row: DelegationRow) -> dict[str, Any]:
    return {
        "delegation_id": row.delegation_id,
        "from_workload": row.from_workload,
        "to_workload": row.to_workload,
        "purposes": row.purposes,
        "expires_at": _iso(row.expires_at),
        "status": row.status,
        "created_at": _iso(row.created_at),
    }


@router.post("/delegations", status_code=201)
def create_delegation(
    request: Request, body: DelegationCreate, session: Session = SessionDep, ident: Identity = AdminDep
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    try:
        row = DelegationStore.create(
            session,
            tenant,
            body.from_workload,
            body.to_workload,
            purposes=body.purposes,
            expires_at=body.expires_at,
            actor=ident.subject,
            at=_now(request),
        )
        session.commit()
    except WorkloadError as exc:  # unknown workload / bad purposes
        session.rollback()
        raise HTTPException(422, detail=str(exc)[:300]) from exc
    except Exception:
        session.rollback()
        raise
    return _delegation_view(row)


@router.delete("/delegations/{delegation_id}")
def revoke_delegation(
    request: Request, delegation_id: str, session: Session = SessionDep, ident: Identity = AdminDep
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    exists = session.scalars(
        select(DelegationRow).where(
            DelegationRow.tenant_id == tenant, DelegationRow.delegation_id == delegation_id
        )
    ).first()
    if exists is None:  # other tenants' delegations are indistinguishable from absent
        raise HTTPException(404, detail="unknown delegation")
    try:
        row = DelegationStore.revoke(session, tenant, delegation_id, actor=ident.subject, at=_now(request))
        session.commit()
    except WorkloadError as exc:
        session.rollback()
        raise HTTPException(404, detail=str(exc)[:300]) from exc
    except Exception:
        session.rollback()
        raise
    return _delegation_view(row)


@router.get("/delegations")
def list_delegations(
    from_workload: str | None = Query(default=None),
    to_workload: str | None = Query(default=None),
    session: Session = SessionDep,
    ident: Identity = ReadDep,
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    rows = DelegationStore.list_all(session, tenant, from_workload=from_workload, to_workload=to_workload)
    return {"delegations": [_delegation_view(r) for r in rows]}


class HandoffRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    from_workload: str = Field(min_length=1, max_length=MAX_ID)
    to_workload: str = Field(min_length=1, max_length=MAX_ID)
    purpose: str = Field(min_length=1, max_length=MAX_ID)


@router.post("/handoffs")
def handoff(
    request: Request, body: HandoffRequest, session: Session = SessionDep, ident: Identity = ReadDep
) -> dict[str, Any]:
    """Authorize an agent-to-agent handoff. DENY is a normal 200 answer, never a 404."""
    tenant = bind_tenant(ident)
    now = _now(request)
    decision, reasons = authorize_handoff(
        session, tenant, body.from_workload, body.to_workload, body.purpose, now
    )
    result = {"decision": decision.value, "reason": [r.value for r in reasons]}
    try:  # fail closed: an unrecorded handoff decision is not served
        audit_append(
            session,
            tenant,
            ident.subject,
            "handoff.authorize",
            {
                "from_workload": body.from_workload,
                "to_workload": body.to_workload,
                "purpose": body.purpose,
                "decision": result["decision"],
                "reason": result["reason"],
            },
            at=now,
        )
        session.commit()
    except Exception:
        session.rollback()
        raise
    return result


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approve: bool = Field(strict=True)  # "yes"/1 are not a decision
    ttl_seconds: int = Field(strict=True, gt=0, le=MAX_TTL_SECONDS)


def _approval_view(row: Any, now: datetime) -> dict[str, Any]:
    state = row.state
    lapsed = state in ("approved", "denied") and (row.expires_at is None or row.expires_at <= now)
    return {
        "approval_id": row.approval_id,
        "state": state,
        "effective_state": "expired" if lapsed else state,
        "fingerprint": row.fingerprint,
        "context": row.decision_context,
        "requested_by_principal": row.requested_by_principal,
        "requested_by_issuer": (row.decision_context.get("principal") or {}).get(
            "issuer"
        ),  # bound by the fingerprint
        "requested_actor": row.requested_actor,
        "decided_by": row.decided_by,
        "decided_at": _iso(row.decided_at),
        "expires_at": _iso(row.expires_at),
        "created_at": _iso(row.created_at),
    }


@router.get("/approvals")
def list_approvals(
    request: Request,
    state: Literal["pending"] = Query(default="pending"),
    session: Session = SessionDep,
    ident: Identity = AdminDep,
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    now = _now(request)
    return {"approvals": [_approval_view(r, now) for r in ApprovalStore.list_pending(session, tenant)]}


@router.get("/approvals/{approval_id}")
def get_approval(
    request: Request, approval_id: str, session: Session = SessionDep, ident: Identity = ReadDep
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    row = ApprovalStore.get(session, tenant, approval_id)  # tenant-scoped: foreign ids look absent
    if row is None:
        raise HTTPException(404, detail="unknown approval")
    return _approval_view(row, _now(request))


@router.post("/approvals/{approval_id}/decide")
def decide_approval(
    request: Request,
    approval_id: str,
    body: ApprovalDecision,
    session: Session = SessionDep,
    ident: Identity = AdminDep,
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    now = _now(request)
    existing = ApprovalStore.get(session, tenant, approval_id)
    if existing is None:
        raise HTTPException(404, detail="unknown approval")
    try:
        row = ApprovalStore.decide(
            session,
            tenant,
            approval_id,
            body.approve,
            ident.subject,
            body.ttl_seconds,
            now=now,
            allow_self=request.app.state.settings.approval_allow_self,
        )
        session.commit()
    except ApprovalError as exc:  # not pending, a concurrent decision won, or separation of duties (409)
        session.rollback()
        raise HTTPException(409, detail=str(exc)[:300]) from exc
    except Exception:
        session.rollback()
        raise
    return _approval_view(row, now)


def metrics_identity(request: Request) -> Identity | None:
    """``read`` role, unless ``ALES_METRICS_PUBLIC=1`` exempted the path from auth (then no identity)."""
    if request.app.state.metrics_public and getattr(request.state, "identity", None) is None:
        return None
    return require("read")(request)


MetricsDep = Depends(metrics_identity)


@router.get("/metrics", response_class=PlainTextResponse)
def metrics(
    request: Request, session: Session = SessionDep, ident: Identity | None = MetricsDep
) -> PlainTextResponse:
    tenant = ident.tenant_id if ident is not None else None
    statement = select(func.count()).select_from(AuditLog)
    if tenant is not None:
        statement = statement.where(AuditLog.tenant_id == tenant)
    audit_total = int(session.scalar(statement) or 0)
    active: tuple[str, int] | None = None
    if tenant is not None:
        document = PolicyStore.get_active(session, tenant)
        active = (document.policy_id, document.version) if document is not None else None
    text = render(
        request.app.state.metrics,
        tenant,
        outbox_totals=outbox_stats(session, tenant)["totals"],
        audit_records=audit_total,
        active_policy=active,
    )
    return PlainTextResponse(text, media_type="text/plain; version=0.0.4; charset=utf-8")
