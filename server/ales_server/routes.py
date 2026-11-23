"""HTTP routes for the Agent Revocation Runtime decision API.

Every route except ``/v1/healthz`` and ``/v1/readyz`` is authenticated by the middleware in
``auth.py``; each route additionally declares the role it needs via ``Depends(require(role))`` and
binds its effective tenant to the credential with ``bind_tenant``. Handlers never read a tenant
from the request without passing it through ``bind_tenant``.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from ales_core import (
    AlesError,
    ApprovalStore,
    AuditLog,
    AuthorizeOutcome,
    AuthorizeRequest,
    AuthorizeResponse,
    ComposedOutcome,
    ContextEnvelope,
    ContextObject,
    EnforcementMode,
    GraphStore,
    InvalidationOutbox,
    IssuerKey,
    KeyRegistry,
    KeyRegistryError,
    RevocationEngine,
    RevocationEvent,
    Tenant,
    apply_composed,
    audit_append,
    audit_head,
    authorize_ex,
    build_provider_request,
    compose_provider_results,
    is_tombstoned,
    needs_provider_call,
    outbox_stats,
    record_decision,
    verify_chain,
    verify_with_registry,
)
from ales_core.audit import GENESIS_HASH
from ales_core.db import lock_tenant
from ales_core.migrations import current_revision, head_revision
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import VERIFY_SUFFIX, Identity, bind_tenant, require
from .config import ConfigError
from .identity import (
    CallerGroupsRejected,
    EntitlementOutcome,
    resolve_for_request,
    restrict_decision,
)
from .metrics import Metrics
from .providers import ProviderRunner
from .telemetry import log_decision, span
from .worker import TenantOutboxDispatcher, handlers_mode

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


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
def readyz(request: Request):
    """Ready iff the database answers and the schema is at the migration head."""
    checks: dict[str, str] = {}
    try:
        with request.app.state.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
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


def _registered(row: Any) -> dict[str, Any]:
    return {"context_id": row.context_id, "object_version": row.object_version, "tenant_id": row.tenant_id}


def _enforce_signature(
    request: Request,
    session: Session,
    obj: ContextEnvelope | RevocationEvent,
    ident: Identity,
    what: str,
    ref: str,
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


def _ensure_auditable(req: AuthorizeRequest) -> None:
    """The ledger refuses long strings; reject such requests up front (422) instead of 500 after deciding."""
    fields = [req.principal.id, req.principal.issuer, req.purpose, req.agent_id, req.session_id, *req.tools]
    for o in req.objects:
        fields += [o.context_id, o.version]
    if any(f is not None and len(f) > MAX_AUDITED_STRING for f in fields):
        raise HTTPException(422, detail=f"identifier longer than {MAX_AUDITED_STRING} characters")


@dataclass
class Decided:
    """A finished decision (lineage -> policy -> external providers) not yet persisted."""

    out: AuthorizeOutcome
    composed: ComposedOutcome | None = None  # None: no providers configured (or none consulted)
    skipped: str | None = None  # why configured providers were not consulted
    revalidated: bool = False  # lineage was re-evaluated after the provider calls (epoch moved)
    identity_extra: dict[str, Any] | None = None  # issuer / entitlement revision + groups (v0.5)

    @property
    def response(self) -> AuthorizeResponse:
        return self.out.response

    def audit_extra(self) -> dict[str, Any]:
        extra = self.out.audit_extra()
        if self.composed is not None:
            extra["external"] = self.composed.audit_detail()
            if self.revalidated:
                extra["external"]["revalidated"] = True
        elif self.skipped is not None:
            extra["external"] = {"skipped": self.skipped}
        if self.identity_extra:
            extra.update(self.identity_extra)
        return extra


def _current_epoch(session: Session, tenant_id: str) -> int:
    return int(session.scalar(select(Tenant.revocation_epoch).where(Tenant.tenant_id == tenant_id)) or 0)


def _decide(
    session: Session,
    req: AuthorizeRequest,
    now: datetime,
    clock: Any,
    *,
    enforce_workloads: EnforcementMode = "auto",
    require_grants: bool = False,
    runner: ProviderRunner | None = None,
    action: str | None = None,
    destination: str | None = None,
) -> Decided:
    """authorize_ex (database) -> provider calls (NO database transaction open) -> compose/restrict.

    The read transaction is ended before any provider I/O so a slow provider never pins a connection or a
    snapshot. Provider answers are bound to the revocation epoch: if the tenant epoch moved while providers
    were being called, lineage and policy are re-evaluated (once) and the provider answers are applied to the
    fresh state, so a revocation that lands mid-call can never be outrun by a stale ALLOW."""
    with span("ales.authorize", tenant_id=req.tenant_id, purpose=req.purpose, objects=len(req.objects)):
        result = authorize_ex(
            session, req, now, enforce_workloads=enforce_workloads, require_grants=require_grants
        )
    if runner is None or not runner.configs:
        return Decided(result)
    if not needs_provider_call(result):
        return Decided(result, skipped=f"base_decision_{result.response.decision.value}")
    preq = build_provider_request(req, result, action=action, destination=destination)
    epoch_seen = result.response.revocation_epoch
    session.rollback()  # end the read transaction: providers are called outside any database transaction
    with span("ales.providers", tenant_id=req.tenant_id, providers=len(runner.configs)):
        pairs, metas = runner.run(preq)
    after = clock()
    revalidated = False
    if _current_epoch(session, req.tenant_id) != epoch_seen:
        result = authorize_ex(
            session, req, after, enforce_workloads=enforce_workloads, require_grants=require_grants
        )
        revalidated = True
    composed = compose_provider_results(pairs, now=after, meta=metas)
    apply_composed(result, composed, session=session, request=req, now=after, destination=destination)
    return Decided(result, composed, revalidated=revalidated)


def _persist_approval(
    session: Session, req: AuthorizeRequest, out: AuthorizeOutcome, actor: str, now: datetime
) -> None:
    if out.approval_required and out.fingerprint is not None and out.approval_context is not None:
        ApprovalStore.ensure_pending(
            session,
            req.tenant_id,
            out.fingerprint,
            out.approval_context,
            actor=actor,
            requested_by_principal=req.principal.id,
            now=now,
        )


def _authorize(
    session: Session,
    req: AuthorizeRequest,
    actor: str,
    now: datetime,
    metrics: Metrics | None = None,
    enforce_workloads: EnforcementMode = "auto",
    require_grants: bool = False,
    runner: ProviderRunner | None = None,
    clock: Any = None,
    entitlements: Callable[[], tuple[AuthorizeRequest, EntitlementOutcome]] | None = None,
) -> AuthorizeResponse:
    ent = EntitlementOutcome()
    if entitlements is not None:
        req, ent = entitlements()
    _ensure_auditable(req)
    decided = _decide(
        session,
        req,
        now,
        clock or (lambda: now),
        enforce_workloads=enforce_workloads,
        require_grants=require_grants,
        runner=runner,
    )
    if entitlements is not None:
        # Membership can change (reload) between resolving groups and stamping the epoch inside the decision;
        # re-resolve once and, if the revision moved, decide again so a stale-group ALLOW is never stamped
        # with the post-change epoch.
        req2, ent2 = entitlements()
        if ent2.revision != ent.revision or ent2.status != ent.status:
            req, ent = req2, ent2
            decided = _decide(
                session,
                req,
                now,
                clock or (lambda: now),
                enforce_workloads=enforce_workloads,
                require_grants=require_grants,
                runner=runner,
            )
        restrict_decision(decided.out, ent)
        decided.identity_extra = ent.audit_extra(req.principal.issuer)
    result, response = decided.out, decided.response
    try:
        # Fail closed: a decision that cannot be recorded is not served. The pending approval (when the
        # policy asks for human review) is created in the same transaction as the decision record.
        _persist_approval(session, req, result, actor, now)
        record_decision(session, actor, req, response, extra=decided.audit_extra())
        session.commit()
    except Exception:
        session.rollback()
        raise
    if metrics is not None:
        metrics.inc("authorize", req.tenant_id, response.decision.value)
    log_decision(
        tenant_id=req.tenant_id,
        principal_id=req.principal.id,
        decision=response.decision.value,
        reasons=[r.value for r in response.reason],
        trace_id=response.trace_id,
    )
    return response


@router.post("/authorize", response_model=AuthorizeResponse)
def authorize_endpoint(
    request: Request, req: AuthorizeRequest, session: Session = SessionDep, ident: Identity = ReadDep
) -> AuthorizeResponse:
    tenant = bind_tenant(ident, req.tenant_id)
    state = request.app.state
    original = req

    def resolve() -> tuple[AuthorizeRequest, EntitlementOutcome]:
        return resolve_for_request(
            state.entitlements, original, tenant, ident, production=state.settings.production
        )

    try:
        resolve()  # fail early (and audit) on caller-asserted groups; the real resolution runs inside _authorize
    except CallerGroupsRejected as exc:
        _ensure_auditable(req)
        audit_append(
            session,
            tenant,
            ident.subject,
            "identity.groups_rejected",
            {
                "principal": {"type": req.principal.type, "id": req.principal.id},
                "reason": exc.reason,
                "count": len(req.groups),
            },
        )
        session.commit()
        raise HTTPException(
            422, detail="groups are resolved by the server; they cannot be asserted by the caller"
        ) from None
    return _authorize(
        session,
        req,
        ident.subject,
        state.clock(),
        state.metrics,
        state.settings.enforce_workloads,
        state.settings.require_grants,
        state.policy_runner,
        state.clock,
        entitlements=resolve,
    )


@router.post("/entitlements/reload")
def entitlements_reload(
    request: Request, session: Session = SessionDep, ident: Identity = AdminDep
) -> dict[str, Any]:
    """Re-read ``ALES_ENTITLEMENTS`` / ``ALES_ENTITLEMENTS_FILE`` and invalidate decisions for tenants whose
    entries changed: their revocation epoch is bumped (conservative: every cached ALLOW of that tenant is
    re-evaluated) and an ``entitlements.reload`` record is appended to each such tenant's ledger.

    The document is process-wide, so this admin call may bump OTHER tenants' epochs when their entries
    changed; the response reveals only the caller's own tenant. A malformed document leaves the previous
    entitlements (and every epoch) untouched. Call it on EVERY replica: each holds its own in-memory copy."""
    tenant = bind_tenant(ident)
    static = request.app.state.entitlements_static
    if static is None:
        raise HTTPException(409, detail="no static entitlement source is configured")
    try:
        changed = static.reload()
    except ConfigError as exc:
        log.error("entitlements reload failed, previous entitlements stay in force: %s", exc)
        raise HTTPException(
            422, detail="entitlement document invalid; previous entitlements remain in force"
        ) from None
    try:
        for t in sorted(changed):
            lock_tenant(session, t)
            session.execute(
                update(Tenant)
                .where(Tenant.tenant_id == t)
                .values(revocation_epoch=Tenant.revocation_epoch + 1)
            )
            audit_append(
                session,
                t,
                ident.subject,
                "entitlements.reload",
                {"revision": static.revision_for(t), "revocation_epoch": _current_epoch(session, t)},
            )
        session.commit()
    except Exception:
        session.rollback()
        raise
    request.app.state.metrics.inc("entitlements_reload", None, "changed" if changed else "unchanged")
    return {
        "reloaded": True,
        "tenant_changed": tenant in changed,
        "revocation_epoch": _current_epoch(session, tenant),
    }


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
            # scope fields omitted: spec v0.4 absent/null = unrestricted ([] would mean NOBODY)
            "classification": "internal",
            "trust_state": "verified",
            "parent_refs": [
                {"context_id": p.context_id, "object_version": p.object_version} for p in parents
            ],
            "policy_version": "p0",
            "valid_from": (
                datetime.now(UTC) - timedelta(minutes=1)
            ).isoformat(),  # scratch chain valid immediately
        }
    )


@router.post("/verify")
def verify(
    request: Request, req: VerifyRequest, session: Session = SessionDep, ident: Identity = IngestDep
) -> dict[str, Any]:
    """Self-test in a scratch namespace ``<tenant>:verify``.

    Requires the ``ingest`` role: it registers objects and a revocation (and writes audit records), so it is
    a write path, not a read.

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

    event = RevocationEvent.model_validate(
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
        epoch = RevocationEngine().accept(session, event, actor=ident.subject)
    check("revocation_epoch_advanced", epoch >= 1, f"epoch={epoch}")

    after = _authorize(session, areq, ident.subject, request.app.state.clock())
    check("authorize_after_revocation_denies", after.decision.value == "DENY", after.decision.value)
    reasons = [r.value for r in after.reason]
    check("deny_reason_ancestor_acl_revoked", "ANCESTOR_ACL_REVOKED" in reasons, ",".join(reasons))
    return result()


@router.get("/snapshot")
def snapshot(request: Request, session: Session = SessionDep, ident: Identity = ReadDep) -> JSONResponse:
    from ales_core import POLICY_VERSION, PolicyStore

    tenant = bind_tenant(ident)
    epoch = session.execute(
        select(Tenant.revocation_epoch).where(Tenant.tenant_id == tenant)
    ).scalar_one_or_none()
    # Sign the tenant's ACTIVE policy version ("<pid>@<ver>"), the same string decisions are stamped with,
    # so offline clients keyed to an older policy_version stop serving stale ALLOWs after an activation.
    document = PolicyStore.get_active(session, tenant)
    signed = request.app.state.snapshot_signer.sign(
        tenant,
        epoch or 0,
        document.policy_version if document is not None else POLICY_VERSION,
        request.app.state.settings.snapshot_lease,
    )
    return JSONResponse(content=signed, headers={"Cache-Control": "no-store"})


@router.get("/snapshot/public_key")
def snapshot_public_key(request: Request, _: Identity = ReadDep) -> dict[str, Any]:
    signer = request.app.state.snapshot_signer
    return {"key_id": signer.key_id, "public_key_b64": signer.public_key_b64, "ephemeral": signer.ephemeral}


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
def patch_key(
    key_id: str, body: KeyPatch, session: Session = SessionDep, ident: Identity = AdminDep
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    registry = KeyRegistry(session)
    existing = registry.get(key_id)
    if (
        existing is None or existing.tenant_id != tenant
    ):  # other tenants' keys are indistinguishable from absent
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
    result = [_key_view(r) for r in rows]
    audit_append(session, tenant, ident.subject, "admin.key.list", {"count": len(result)})
    session.commit()
    return {"keys": result}


@router.get("/audit/verify")
def audit_verify(session: Session = SessionDep, ident: Identity = AdminDep) -> dict[str, Any]:
    """Recompute the tenant's chains. Read-only: verification never appends to the ledger it is checking."""
    tenant = bind_tenant(ident)
    if session.get_bind().dialect.name == "postgresql":
        session.execute(text("SET TRANSACTION READ ONLY"))
    bad: list[int] = []
    for t in (tenant, tenant + VERIFY_SUFFIX):  # the tenant's chain and its verify scratch chain
        ok, first = verify_chain(session, t)
        if not ok and first is not None:
            bad.append(first)
    first_bad = min(bad) if bad else None
    n = session.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.tenant_id == tenant))
    # no audit_append and no commit: the transaction ends with the request (rolled back on close)
    return {"ok": first_bad is None, "first_bad_seq": first_bad, "records_checked": n}


@router.get("/audit/head")
def audit_head_endpoint(
    request: Request, session: Session = SessionDep, ident: Identity = ReadDep
) -> dict[str, Any]:
    """Newest audit record of the caller's tenant chain, for external anchoring (R23).

    ``seq`` / ``head_hash`` identify the newest record (``0`` / the genesis hash for an empty chain); ``at`` is
    the server time the head was read. Anchor it outside the database; a later head that does not extend an
    anchored one proves truncation or rewrite.
    """
    tenant = bind_tenant(ident)
    h = audit_head(session, tenant)
    seq, head_hash = h if h is not None else (0, GENESIS_HASH)
    return {
        "tenant_id": tenant,
        "seq": seq,
        "head_hash": head_hash,
        "at": request.app.state.clock().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }


@router.get("/outbox/stats")
def outbox_stats_endpoint(
    request: Request, session: Session = SessionDep, ident: Identity = ReadDep
) -> dict[str, Any]:
    stats = outbox_stats(session, ident.tenant_id)
    worker = request.app.state.outbox_worker
    stats["worker"] = {
        "running": bool(worker and worker.running),
        "interval_seconds": request.app.state.settings.outbox_interval,
        "handlers": (
            "deny_only"
            if request.app.state.settings.purge_policy == "deny-only"
            else handlers_mode(request.app.state.outbox_handlers)
        ),
    }
    return stats


DEAD_LIST_MAX = 500


def _dead_view(row: InvalidationOutbox) -> dict[str, Any]:
    return {
        "id": row.id,
        "context_id": row.context_id,
        "version": row.version,
        "store_kind": row.store_kind,
        "attempts": row.attempts,
        "last_error": row.last_error,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/outbox/dead")
def outbox_dead(
    limit: int = Query(default=100, ge=1, le=DEAD_LIST_MAX),
    after_id: int = Query(default=0, ge=0),
    session: Session = SessionDep,
    ident: Identity = AdminDep,
) -> dict[str, Any]:
    """Dead-lettered purge rows of the caller's tenant (R11). ``after_id`` pages by ascending row id."""
    tenant = bind_tenant(ident)
    rows = session.scalars(
        select(InvalidationOutbox)
        .where(
            InvalidationOutbox.tenant_id == tenant,
            InvalidationOutbox.state == "dead",
            InvalidationOutbox.id > after_id,
        )
        .order_by(InvalidationOutbox.id)
        .limit(limit)
    )
    return {"dead": [_dead_view(r) for r in rows]}


@router.post("/outbox/dead/{row_id}/requeue")
def outbox_requeue(row_id: int, session: Session = SessionDep, ident: Identity = AdminDep) -> dict[str, Any]:
    """Return one dead row of the caller's tenant to ``pending`` with its attempt budget reset (audited)."""
    tenant = bind_tenant(ident)
    row = session.scalar(
        select(InvalidationOutbox).where(
            InvalidationOutbox.id == row_id, InvalidationOutbox.tenant_id == tenant
        )
    )
    if row is None:  # another tenant's row is indistinguishable from absent
        raise HTTPException(404, detail="unknown outbox row")
    detail = {
        "outbox_id": row_id,
        "context_id": _clip(row.context_id),
        "version": _clip(row.version),
        "store_kind": _clip(row.store_kind),
        "attempts_before": row.attempts,
    }
    try:
        result = session.execute(
            update(InvalidationOutbox)
            .where(
                InvalidationOutbox.id == row_id,
                InvalidationOutbox.tenant_id == tenant,
                InvalidationOutbox.state == "dead",
            )
            .values(
                state="pending",
                attempts=0,
                lease_token=None,
                lease_expires_at=None,
                last_error=None,
                dispatched=False,
                available_at=datetime.now(UTC),
            )
        )
        if int(getattr(result, "rowcount", 0) or 0) != 1:
            session.rollback()
            raise HTTPException(409, detail=f"outbox row is '{row.state}', not 'dead'")
        audit_append(session, tenant, ident.subject, "admin.outbox.requeue", detail)
        session.commit()
    except HTTPException:
        raise
    except Exception:
        session.rollback()
        raise
    return {"id": row_id, "state": "pending", "attempts": 0}


@router.post("/outbox/run")
def outbox_run(request: Request, ident: Identity = AdminDep) -> dict[str, Any]:
    """Run the dispatcher once, now, over the caller's tenant's due rows only (operators, drills, tests).

    Safe alongside the background worker: leasing is a compare-and-swap. Returns the dispatcher's counts.
    """
    tenant = bind_tenant(ident)
    dispatcher = TenantOutboxDispatcher(
        tenant, request.app.state.session_factory, request.app.state.outbox_handlers
    )
    r = dispatcher.run_once()
    return {
        "leased": r.leased,
        "done": r.done,
        "failed": r.failed,
        "dead": r.dead,
        "lost_lease": r.lost_lease,
    }


MAX_RECONCILE_IDS = 10000


class ReconcileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    store_kind: str = Field(min_length=1, max_length=32)
    known_ids: list[str] = Field(max_length=MAX_RECONCILE_IDS)


@router.post("/outbox/reconcile")
def outbox_reconcile(
    body: ReconcileRequest, request: Request, session: Session = SessionDep, ident: Identity = AdminDep
) -> dict[str, Any]:
    """Operator-triggered store reconciliation.

    The operator scans a downstream store (see ``scripts/ales_store_scan.py``) and posts the context ids it
    found. Returns ``tombstoned`` (present in the store although revoked: purge is owed or was missed, e.g. a
    cache data key whose reverse-index write never landed so the purge handler could not find it, with the
    outbox state of that object), ``untracked`` (ids this tenant never registered: orphans of a failed or
    crashed registration) and ``ok``. Read-only apart from an audit record; nothing is purged here.
    """
    tenant = bind_tenant(ident)
    ids = sorted(set(body.known_ids))
    now = request.app.state.clock()
    rows: dict[str, list[ContextObject]] = {}
    for i in range(0, len(ids), 500):
        for r in session.scalars(
            select(ContextObject).where(
                ContextObject.tenant_id == tenant, ContextObject.context_id.in_(ids[i : i + 500])
            )
        ):
            rows.setdefault(r.context_id, []).append(r)
    tombstoned: list[dict[str, Any]] = []
    untracked: list[str] = []
    ok: list[str] = []
    for context_id in ids:
        versions = rows.get(context_id)
        if not versions:
            untracked.append(context_id)
            continue
        dead = [v for v in versions if is_tombstoned(session, tenant, v.context_id, v.object_version, now)]
        if not dead:
            ok.append(context_id)
            continue
        states = sorted(
            {
                st
                for (st,) in session.execute(
                    select(InvalidationOutbox.state).where(
                        InvalidationOutbox.tenant_id == tenant,
                        InvalidationOutbox.context_id == context_id,
                        InvalidationOutbox.store_kind == body.store_kind,
                    )
                )
            }
        )
        tombstoned.append(
            {
                "context_id": context_id,
                "versions": sorted(v.object_version for v in dead),
                "outbox_states": states,
                "purge_row_done": "done" in states,
            }
        )
    audit_append(
        session,
        tenant,
        ident.subject,
        "admin.outbox.reconcile",
        {
            "store_kind": body.store_kind,
            "scanned": len(ids),
            "tombstoned": len(tombstoned),
            "untracked": len(untracked),
        },
    )
    session.commit()
    return {
        "store_kind": body.store_kind,
        "scanned": len(ids),
        "tombstoned": tombstoned,
        "untracked": untracked,
        "ok": ok,
    }
