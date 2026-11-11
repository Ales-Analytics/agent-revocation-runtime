"""HTTP routes for the ALES INVARIANT decision API."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from ales_core import (
    AlesError,
    AuthorizeRequest,
    AuthorizeResponse,
    ContextEnvelope,
    GraphStore,
    RevocationEngine,
    RevocationEvent,
    authorize,
)
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .telemetry import log_decision, span

router = APIRouter(prefix="/v1")


def get_session(request: Request):
    yield from request.app.state.get_session()


SessionDep = Depends(get_session)


def _check_tenant(header: str | None, body_tenant: str | None) -> str | None:
    if header and body_tenant and header != body_tenant:
        raise HTTPException(409, detail={"error": "tenant_mismatch", "header": header, "body": body_tenant})
    return body_tenant or header


class VerifyRequest(BaseModel):
    tenant_id: str
    adapter: str = "builtin"
    mode: str = "strict"


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def _registered(row: Any) -> dict[str, Any]:
    return {"context_id": row.context_id, "object_version": row.object_version, "tenant_id": row.tenant_id}


@router.post("/sources")
def register_source(
    env: ContextEnvelope, session: Session = SessionDep, x_tenant_id: str | None = Header(default=None)
) -> dict[str, Any]:
    _check_tenant(x_tenant_id, env.tenant_id)
    try:
        row = GraphStore(session).register_source(env)
        session.commit()
    except Exception:
        session.rollback()
        raise
    return _registered(row)


@router.post("/derivations")
def register_derivation(
    env: ContextEnvelope, session: Session = SessionDep, x_tenant_id: str | None = Header(default=None)
) -> dict[str, Any]:
    _check_tenant(x_tenant_id, env.tenant_id)
    try:
        row = GraphStore(session).register_derivation(env)
        session.commit()
    except Exception:
        session.rollback()
        raise
    return _registered(row)


@router.post("/revocations")
def submit_revocation(
    body: dict[str, Any],
    session: Session = SessionDep,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    tenant = _check_tenant(x_tenant_id, body.get("tenant_id"))
    data = dict(body)
    if tenant:
        data.setdefault("tenant_id", tenant)
    data.setdefault("event_id", str(uuid.uuid4()))
    data.setdefault("effective_at", datetime.now(UTC).isoformat())
    event = RevocationEvent.model_validate(data)  # ValidationError -> 422 via app handler
    with span("ales.revocation", tenant_id=event.tenant_id, reason=event.reason.value):
        epoch = RevocationEngine().accept(session, event)
    return {"event_id": event.event_id, "revocation_epoch": epoch}


def _authorize(session: Session, req: AuthorizeRequest) -> AuthorizeResponse:
    with span("ales.authorize", tenant_id=req.tenant_id, purpose=req.purpose, objects=len(req.objects)):
        resp = authorize(session, req, datetime.now(UTC))
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
    req: AuthorizeRequest, session: Session = SessionDep, x_tenant_id: str | None = Header(default=None)
) -> AuthorizeResponse:
    _check_tenant(x_tenant_id, req.tenant_id)
    return _authorize(session, req)


@router.get("/lineage/{context_id}")
def lineage(
    context_id: str,
    tenant_id: str | None = Query(default=None),
    version: str | None = Query(default=None),
    session: Session = SessionDep,
    x_tenant_id: str | None = Header(default=None),
) -> dict[str, Any]:
    tenant = _check_tenant(x_tenant_id, tenant_id)
    if not tenant:
        raise HTTPException(422, detail="tenant_id query parameter or X-Tenant-Id header required")
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

    def describe(nodes: dict[tuple[str, str], None]) -> list[dict[str, Any]]:
        rows = graph.load_objects(tenant, list(nodes))
        return [
            {
                "context_id": n[0],
                "object_version": n[1],
                "kind": rows[n].kind if n in rows else None,
                "tombstoned": rows[n].tombstoned if n in rows else None,
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
def verify(
    req: VerifyRequest, session: Session = SessionDep, x_tenant_id: str | None = Header(default=None)
) -> dict[str, Any]:
    _check_tenant(x_tenant_id, req.tenant_id)
    tenant = req.tenant_id + ":verify"
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "passed": bool(ok), "detail": detail})

    def result() -> dict[str, Any]:
        return {
            "passed": bool(checks) and all(c["passed"] for c in checks),
            "adapter": req.adapter,
            "mode": req.mode,
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
    before = _authorize(session, areq)
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
        epoch = RevocationEngine().accept(session, ev)
    check("revocation_epoch_advanced", epoch >= 1, f"epoch={epoch}")

    after = _authorize(session, areq)
    check("authorize_after_revocation_denies", after.decision.value == "DENY", after.decision.value)
    reasons = [r.value for r in after.reason]
    check("deny_reason_ancestor_acl_revoked", "ANCESTOR_ACL_REVOKED" in reasons, ",".join(reasons))
    return result()
