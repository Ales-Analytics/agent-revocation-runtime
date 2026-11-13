"""HTTP routes for the ALES INVARIANT decision API.

Every route except ``/v1/healthz`` and ``/v1/readyz`` is authenticated by the middleware in
``auth.py``; each route additionally declares the role it needs via ``Depends(require(role))`` and
binds its effective tenant to the credential with ``bind_tenant``. Handlers never read a tenant
from the request without passing it through ``bind_tenant``.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from ales_core import (
    AlesError,
    ApprovalStore,
    AuditLog,
    AuthorizeRequest,
    AuthorizeResponse,
    ContextEnvelope,
    EnforcementMode,
    GraphStore,
    IssuerKey,
    KeyRegistry,
    KeyRegistryError,
    RevocationEngine,
    RevocationEvent,
    Tenant,
    audit_append,
    authorize_ex,
    is_tombstoned,
    outbox_stats,
    record_decision,
    verify_chain,
    verify_with_registry,
)
from ales_core.migrations import current_revision, head_revision
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import VERIFY_SUFFIX, Identity, bind_tenant, require
from .metrics import Metrics
from .telemetry import log_decision, span
from .worker import handlers_mode

log = logging.getLogger("ales.server")

router = APIRouter(prefix="/v1")

#: audit ``detail`` strings above this are refused by the ledger; clip attacker-controlled values.
AUDIT_CLIP = 128
MAX_AUDITED_STRING = 512


def get_session(request: Request):
    yield from request.app.state.get_session()


SessionDep = Depends(get_session)
IngestDep = Depends(require("ingest"))
RevokeDep = Depends(require("revoke"))
ReadDep = Depends(require("read"))
AdminDep = Depends(require("admin"))


def wall_clock() -> datetime:
    """Default decision-path clock. Looks up ``datetime`` in this module at call time on purpose: the
    RevocationBench harness shifts time by patching ``ales_server.routes.datetime``."""
    return datetime.now(UTC)


def _clip(value: str | None, n: int = AUDIT_CLIP) -> str | None:
    return None if value is None else value[:n]


class VerifyRequest(BaseModel):
    tenant_id: str
    adapter: str = "builtin"
    mode: str = "strict"


# ----------------------------------------------------------------------------------- ops (public)
@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
def readyz(request: Request):
    """Ready iff the database answers and the schema is at the migration head."""
    checks: dict[str, str] = {}
    try:
        with request.app.state.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:  # noqa: BLE001 - never leak driver errors to an unauthenticated caller
        checks["database"] = "unavailable"
    if checks["database"] == "ok":
        try:
            at = current_revision(request.app.state.engine)
            checks["migrations"] = "ok" if at == head_revision() else "behind"
        except Exception:  # noqa: BLE001
            checks["migrations"] = "unavailable"
    ready = all(v == "ok" for v in checks.values()) and len(checks) == 2
    body = {"status": "ready" if ready else "unavailable", "checks": checks}
    return JSONResponse(status_code=200 if ready else 503, content=body)


# ---------------------------------------------------------------------------------------- ingress
def _registered(row: Any) -> dict[str, Any]:
    return {"context_id": row.context_id, "object_version": row.object_version, "tenant_id": row.tenant_id}


def _enforce_signature(
    request: Request, session: Session, obj: ContextEnvelope | RevocationEvent, ident: Identity, what: str, ref: str
) -> None:
    """When require_signatures is on, reject (403, reason) anything not signed by an active tenant key."""
    if not request.app.state.settings.require_signatures:
        return
    result = verify_with_registry(session, obj)
    if result.ok:
        return
    audit_append(
        session,
        obj.tenant_id,
        ident.subject,
        "ingress.rejected",
        {"what": what, "ref": ref, "reason": result.reason, "key_id": _clip(result.key_id)},
    )
    session.commit()
    # The true reason is audited above; the wire response collapses cross_tenant_key to
    # unknown_key so a caller cannot probe whether a key_id exists under another tenant.
    wire_reason = "unknown_key" if result.reason == "cross_tenant_key" else result.reason
    raise HTTPException(403, detail=wire_reason)


def _register(
    request: Request, session: Session, env: ContextEnvelope, ident: Identity, *, derivation: bool
) -> dict[str, Any]:
    tenant = bind_tenant(ident, env.tenant_id)
    what = "derivation" if derivation else "source"
    _enforce_signature(request, session, env, ident, what, env.context_id)
    try:
        graph = GraphStore(session)
        row = graph.register_derivation(env) if derivation else graph.register_source(env)
        audit_append(
            session,
            tenant,
            ident.subject,
            f"{what}.register",
            {
                "context_id": env.context_id,
                "object_version": _clip(env.object_version),
                "kind": env.kind.value,
                "signed": bool(env.signature),
                "issuer_key_id": _clip(env.issuer_key_id),
            },
        )
        session.commit()
    except Exception:
        session.rollback()
        raise
    return _registered(row)


@router.post("/sources")
def register_source(
    request: Request, env: ContextEnvelope, session: Session = SessionDep, ident: Identity = IngestDep
) -> dict[str, Any]:
    return _register(request, session, env, ident, derivation=False)


@router.post("/derivations")
def register_derivation(
    request: Request, env: ContextEnvelope, session: Session = SessionDep, ident: Identity = IngestDep
) -> dict[str, Any]:
    return _register(request, session, env, ident, derivation=True)


@router.post("/revocations")
def submit_revocation(
    request: Request,
    body: dict[str, Any],
    session: Session = SessionDep,
    ident: Identity = RevokeDep,
) -> dict[str, Any]:
    tenant = bind_tenant(ident, body.get("tenant_id"))
    data = dict(body)
    data["tenant_id"] = tenant
    data.setdefault("event_id", str(uuid.uuid4()))
    data.setdefault("effective_at", datetime.now(UTC).isoformat())
    event = RevocationEvent.model_validate(data)  # ValidationError -> 422 via app handler
    _enforce_signature(request, session, event, ident, "revocation", event.event_id)
    with span("ales.revocation", tenant_id=event.tenant_id, reason=event.reason.value):
        epoch = RevocationEngine().accept(session, event, actor=ident.subject)
    request.app.state.metrics.inc("revocation", event.tenant_id)
    return {"event_id": event.event_id, "revocation_epoch": epoch}


# --------------------------------------------------------------------------------------- decisions
def _ensure_auditable(req: AuthorizeRequest) -> None:
    """The ledger refuses long strings; reject such requests up front (422) instead of 500 after deciding."""
    fields = [req.principal.id, req.purpose, req.agent_id, req.session_id, *req.tools]
    for o in req.objects:
        fields += [o.context_id, o.version]
    if any(f is not None and len(f) > MAX_AUDITED_STRING for f in fields):
        raise HTTPException(422, detail=f"identifier longer than {MAX_AUDITED_STRING} characters")


def _authorize(
    session: Session,
    req: AuthorizeRequest,
    actor: str,
    now: datetime,
    metrics: Metrics | None = None,
    enforce_workloads: EnforcementMode = "auto",
) -> AuthorizeResponse:
    _ensure_auditable(req)
    with span("ales.authorize", tenant_id=req.tenant_id, purpose=req.purpose, objects=len(req.objects)):
        out = authorize_ex(session, req, now, enforce_workloads=enforce_workloads)
    resp = out.response
    try:
        # Fail closed: a decision that cannot be recorded is not served. The pending approval (when the
        # policy asks for human review) is created in the same transaction as the decision record.
        if out.approval_required and out.fingerprint is not None and out.approval_context is not None:
            ApprovalStore.ensure_pending(
                session, req.tenant_id, out.fingerprint, out.approval_context, actor=actor,
                requested_by_principal=req.principal.id, now=now,
            )
        record_decision(session, actor, req, resp, extra=out.audit_extra())
        session.commit()
    except Exception:
        session.rollback()
        raise
    if metrics is not None:
        metrics.inc("authorize", req.tenant_id, resp.decision.value)
    log_decision(
        tenant_id=req.tenant_id,
        principal_id=req.principal.id,
        decision=resp.decision.value,
        reasons=[r.value for r in resp.reason],
        trace_id=resp.trace_id,
    )
    return resp


@router.post("/authorize", response_model=AuthorizeResponse)
def authorize_endpoint(
    request: Request, req: AuthorizeRequest, session: Session = SessionDep, ident: Identity = ReadDep
) -> AuthorizeResponse:
    bind_tenant(ident, req.tenant_id)
    return _authorize(
        session, req, ident.subject, request.app.state.clock(), request.app.state.metrics,
        request.app.state.settings.enforce_workloads,
    )


@router.get("/lineage/{context_id}")
def lineage(
    context_id: str,
    tenant_id: str | None = Query(default=None),
    version: str | None = Query(default=None),
    session: Session = SessionDep,
    ident: Identity = ReadDep,
) -> dict[str, Any]:
    tenant = bind_tenant(ident, tenant_id)
    graph = GraphStore(session)
    versions = graph.get_versions(tenant, context_id)
    if version is not None:
        versions = [v for v in versions if v.object_version == version]
    if not versions:
        raise HTTPException(404, detail={"error": "unknown_context", "context_id": context_id})

    anc: dict[tuple[str, str], None] = {}
    desc: dict[tuple[str, str], None] = {}
    for v in versions:
        for n in graph.get_ancestors(tenant, v.context_id, v.object_version):
            anc[n] = None
        for n in graph.get_descendants(tenant, v.context_id, v.object_version):
            desc[n] = None

    now = datetime.now(UTC)

    def describe(nodes: dict[tuple[str, str], None]) -> list[dict[str, Any]]:
        rows = graph.load_objects(tenant, list(nodes))
        return [
            {
                "context_id": n[0],
                "object_version": n[1],
                "kind": rows[n].kind if n in rows else None,
                # time-correct (honours effective_at and ancestors), not the informational column
                "tombstoned": is_tombstoned(session, tenant, n[0], n[1], now) if n in rows else None,
            }
            for n in sorted(nodes)
        ]

    return {"context_id": context_id, "ancestors": describe(anc), "descendants": describe(desc)}


def _envelope(tenant: str, kind: str, name: str, parents: list[ContextEnvelope]) -> ContextEnvelope:
    return ContextEnvelope.model_validate(
        {
            "context_id": str(uuid.uuid4()),
            "tenant_id": tenant,
            "object_id": name,
            "object_version": "1",
            "content_digest": "sha256:" + uuid.uuid4().hex + uuid.uuid4().hex,
            "kind": kind,
            "source_system": "ales-verify",
            "principal_scope": [],
            "purpose_scope": [],
            "classification": "internal",
            "trust_state": "verified",
            "parent_refs": [
                {"context_id": p.context_id, "object_version": p.object_version} for p in parents
            ],
            "policy_version": "p0",
            "valid_from": datetime.now(UTC).isoformat(),
        }
    )


@router.post("/verify")
def verify(request: Request, req: VerifyRequest, session: Session = SessionDep, ident: Identity = ReadDep) -> dict[str, Any]:
    """Self-test in a scratch namespace ``<tenant>:verify``.

    Tenants may not end in that suffix (enforced for tokens and anonymous callers), so the scratch
    data can never collide with a real tenant. Scratch registrations are unsigned by design and do
    not pass through signature ingress; they cannot reach real tenant data.
    """
    base = bind_tenant(ident, req.tenant_id)
    tenant = base + VERIFY_SUFFIX
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "passed": bool(ok), "detail": detail})

    def result() -> dict[str, Any]:
        return {
            "passed": bool(checks) and all(c["passed"] for c in checks),
            "adapter": req.adapter[:128],
            "mode": req.mode[:128],
            "checks": checks,
        }

    graph = GraphStore(session)
    try:
        src = _envelope(tenant, "source", "verify/source", [])
        chunk = _envelope(tenant, "chunk", "verify/chunk", [src])
        summ = _envelope(tenant, "summary", "verify/summary", [chunk])
        graph.register_source(src)
        graph.register_derivation(chunk)
        graph.register_derivation(summ)
        session.commit()
        check("register_chain", True, "source -> chunk -> summary registered")
    except AlesError as e:  # report instead of raising
        session.rollback()
        check("register_chain", False, type(e).__name__)
        return result()

    areq = AuthorizeRequest.model_validate(
        {
            "tenant_id": tenant,
            "principal": {"type": "service", "id": "ales-verify"},
            "purpose": "verify",
            "objects": [{"context_id": summ.context_id}],
        }
    )
    before = _authorize(session, areq, ident.subject, request.app.state.clock())
    check("authorize_before_revocation_allows", before.decision.value == "ALLOW", before.decision.value)

    ev = RevocationEvent.model_validate(
        {
            "event_id": str(uuid.uuid4()),
            "tenant_id": tenant,
            "source_id": src.context_id,
            "reason": "acl_changed",
            "effective_at": datetime.now(UTC).isoformat(),
            "actor": "ales-verify",
        }
    )
    with span("ales.revocation", tenant_id=tenant, reason="acl_changed"):
        epoch = RevocationEngine().accept(session, ev, actor=ident.subject)
    check("revocation_epoch_advanced", epoch >= 1, f"epoch={epoch}")

    after = _authorize(session, areq, ident.subject, request.app.state.clock())
    check("authorize_after_revocation_denies", after.decision.value == "DENY", after.decision.value)
    reasons = [r.value for r in after.reason]
    check("deny_reason_ancestor_acl_revoked", "ANCESTOR_ACL_REVOKED" in reasons, ",".join(reasons))
    return result()


# --------------------------------------------------------------------------------------- snapshots
@router.get("/snapshot")
def snapshot(request: Request, session: Session = SessionDep, ident: Identity = ReadDep) -> JSONResponse:
    from ales_core import POLICY_VERSION

    tenant = bind_tenant(ident)
    epoch = session.execute(select(Tenant.revocation_epoch).where(Tenant.tenant_id == tenant)).scalar_one_or_none()
    signed = request.app.state.snapshot_signer.sign(
        tenant, epoch or 0, POLICY_VERSION, request.app.state.settings.snapshot_lease
    )
    return JSONResponse(content=signed, headers={"Cache-Control": "no-store"})


@router.get("/snapshot/public_key")
def snapshot_public_key(request: Request, _: Identity = ReadDep) -> dict[str, Any]:
    signer = request.app.state.snapshot_signer
    return {"key_id": signer.key_id, "public_key_b64": signer.public_key_b64, "ephemeral": signer.ephemeral}


# ------------------------------------------------------------------------------------------- admin
class KeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(min_length=1, max_length=128)
    tenant_id: str | None = None
    public_key_b64: str = Field(min_length=1, max_length=128)


class KeyPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["active", "retired", "revoked"]


def _key_view(row: IssuerKey) -> dict[str, Any]:
    return {
        "key_id": row.key_id,
        "tenant_id": row.tenant_id,
        "public_key_b64": row.public_key_b64,
        "status": row.status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.post("/admin/keys", status_code=201)
def create_key(body: KeyCreate, session: Session = SessionDep, ident: Identity = AdminDep) -> dict[str, Any]:
    tenant = bind_tenant(ident, body.tenant_id)  # tenant is ALWAYS the credential's
    registry = KeyRegistry(session)
    try:
        if registry.get(body.key_id) is not None:
            raise HTTPException(409, detail="key_id already registered")
        row = registry.register_key(tenant, body.key_id, body.public_key_b64)
        audit_append(
            session, tenant, ident.subject, "admin.key.register", {"key_id": body.key_id, "status": "active"}
        )
        session.commit()
    except KeyRegistryError as exc:
        session.rollback()
        raise HTTPException(422, detail=str(exc)[:200]) from exc
    except IntegrityError as exc:  # concurrent registration of the same key_id
        session.rollback()
        raise HTTPException(409, detail="key_id already registered") from exc
    except Exception:
        session.rollback()
        raise
    return _key_view(row)


@router.patch("/admin/keys/{key_id}")
def patch_key(key_id: str, body: KeyPatch, session: Session = SessionDep, ident: Identity = AdminDep) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    registry = KeyRegistry(session)
    existing = registry.get(key_id)
    if existing is None or existing.tenant_id != tenant:  # other tenants' keys are indistinguishable from absent
        raise HTTPException(404, detail="unknown key")
    previous = existing.status
    try:
        row = registry.set_status(tenant, key_id, body.status)
        audit_append(
            session,
            tenant,
            ident.subject,
            "admin.key.set_status",
            {"key_id": _clip(key_id), "from": previous, "to": body.status},
        )
        session.commit()
    except KeyRegistryError as exc:
        session.rollback()
        raise HTTPException(409, detail=str(exc)[:200]) from exc
    except Exception:
        session.rollback()
        raise
    return _key_view(row)


@router.get("/admin/keys")
def list_keys(session: Session = SessionDep, ident: Identity = AdminDep) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    rows = session.scalars(select(IssuerKey).where(IssuerKey.tenant_id == tenant).order_by(IssuerKey.key_id))
    out = [_key_view(r) for r in rows]
    audit_append(session, tenant, ident.subject, "admin.key.list", {"count": len(out)})
    session.commit()
    return {"keys": out}


@router.get("/audit/verify")
def audit_verify(session: Session = SessionDep, ident: Identity = AdminDep) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    bad: list[int] = []
    for t in (tenant, tenant + VERIFY_SUFFIX):  # the tenant's chain and its verify scratch chain
        ok, first = verify_chain(session, t)
        if not ok and first is not None:
            bad.append(first)
    first_bad = min(bad) if bad else None
    n = session.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.tenant_id == tenant))
    # recorded after verification so the check itself does not mask a break it just found
    audit_append(
        session, tenant, ident.subject, "admin.audit.verify", {"ok": first_bad is None, "first_bad_seq": first_bad}
    )
    session.commit()
    return {"ok": first_bad is None, "first_bad_seq": first_bad, "records_checked": n}


# ------------------------------------------------------------------------------------------ outbox
@router.get("/outbox/stats")
def outbox_stats_endpoint(request: Request, session: Session = SessionDep, ident: Identity = ReadDep) -> dict[str, Any]:
    stats = outbox_stats(session, ident.tenant_id)
    worker = request.app.state.outbox_worker
    stats["worker"] = {
        "running": bool(worker and worker.running),
        "interval_seconds": request.app.state.settings.outbox_interval,
        "handlers": handlers_mode(request.app.state.outbox_handlers),
    }
    return stats
