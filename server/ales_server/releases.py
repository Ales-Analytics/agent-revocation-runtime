"""``POST /v1/releases``: the release gate (spec v0.4).

Authorizes an outward action immediately before execution. The gate re-authorizes every object (full
lineage + built-in policy + external providers) for the ``(action, destination)`` pair and returns a
short-lived release receipt. Executing the side effect is the caller's job; the receipt bounds but cannot
eliminate the race between this check and the side effect.

Conventions:

* ``purpose`` is the request purpose; ``action`` and ``destination`` are passed to providers and audited.
* With ``workload`` the action is checked as the tool-like capability ``action:<action>`` (the existing
  ``tool:`` prefixed form also matches), under the SAME opt-in workload gate as ``/v1/authorize``
  (``ALES_ENFORCE_WORKLOADS`` / grants). Suspended or unknown workloads are denied. Delegation/handoff gating
  does NOT apply here (that is ``/v1/handoffs``).
* ``tools`` of the internal authorize request is ``["action:<action>"]``, so policy ``resources.tools`` rules
  can target actions too.
* Every call is audited ``release.authorize`` and stored in ``release_receipts`` (identifiers only).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Annotated, Any

from ales_core import (
    AuthorizeRequest,
    Decision,
    ObjectRef,
    Principal,
    ReleaseReceipt,
    ReleaseReceiptRow,
    audit_append,
    canonicalize,
    new_receipt_id,
    release_capability,
    release_reasons,
)
from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy.orm import Session

from .auth import Identity, bind_tenant
from .identity import resolve_for_request, restrict_decision
from .routes import MAX_AUDITED_STRING, ReadDep, SessionDep, _decide, _ensure_auditable, _persist_approval

router = APIRouter(prefix="/v1")

Short = Annotated[str, StringConstraints(min_length=1, max_length=255)]
MAX_RELEASE_TTL = 3600


class ReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str | None = None
    principal: Principal
    workload: Short | None = None
    action: Short
    destination: Short
    purpose: Short
    objects: list[ObjectRef] = Field(min_length=1, max_length=256)
    session_id: str | None = Field(default=None, max_length=MAX_AUDITED_STRING)


def _fp(tenant: str, body: ReleaseRequest, policy_version: str, objs: list[tuple[str, str | None]]) -> str:
    payload = {
        "tenant": tenant,
        "principal": body.principal.model_dump(),  # includes ``issuer`` only when present (old receipts unchanged)
        "workload": body.workload,
        "action": body.action,
        "destination": body.destination,
        "purpose": body.purpose,
        "objects": sorted([c, v or ""] for c, v in objs),
        "policy_version": policy_version,
    }
    return hashlib.sha256(canonicalize(payload)).hexdigest()


@router.post("/releases", response_model=ReleaseReceipt)
def release(
    request: Request, body: ReleaseRequest, session: Session = SessionDep, ident: Identity = ReadDep
) -> ReleaseReceipt:
    tenant = bind_tenant(ident, body.tenant_id)
    state = request.app.state
    areq = AuthorizeRequest(
        tenant_id=tenant, principal=body.principal, purpose=body.purpose, agent_id=body.workload,
        session_id=body.session_id, objects=body.objects, tools=[release_capability(body.action)],
    )
    _ensure_auditable(areq)
    now = state.clock()

    def decide(r: AuthorizeRequest) -> Any:
        return _decide(
            session, r, now, state.clock, enforce_workloads=state.settings.enforce_workloads,
            require_grants=state.settings.require_grants, runner=state.policy_runner,
            action=body.action, destination=body.destination,
        )

    # Entitlements resolve exactly like POST /v1/authorize (R46 closed): the server resolves ``groups`` for
    # the principal, a changed revision during the decision triggers one re-decision, and an unavailable
    # required provider restricts the verdict the same way. The release body carries no ``groups`` field, so
    # caller-asserted groups cannot reach this path.
    original = areq

    def resolve() -> tuple[AuthorizeRequest, Any]:
        return resolve_for_request(state.entitlements, original, tenant, ident, production=state.settings.production)

    areq, ent = resolve()
    decided = decide(areq)
    req2, ent2 = resolve()
    if ent2.revision != ent.revision or ent2.status != ent.status:
        areq, ent = req2, ent2
        decided = decide(areq)
    restrict_decision(decided.out, ent)
    decided.identity_extra = ent.audit_extra(areq.principal.issuer)
    out, resp = decided.out, decided.response
    receipt_id = new_receipt_id()
    issued = state.clock()
    until = issued  # a refusal is never usable
    if resp.decision == Decision.ALLOW:
        until = issued + timedelta(seconds=min(state.settings.release_ttl, MAX_RELEASE_TTL))
        if resp.valid_until is not None:
            until = min(until, datetime.fromisoformat(resp.valid_until))
    reasons = release_reasons(resp.decision, list(resp.reason))
    receipt = ReleaseReceipt(
        receipt_id=receipt_id,
        decision=resp.decision,
        reason=reasons,
        valid_until=until.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        revocation_epoch=resp.revocation_epoch,
        policy_version=resp.policy_version,
    )
    fp = _fp(tenant, body, resp.policy_version, [(v.context_id, v.version) for v in resp.objects])
    detail: dict[str, Any] = {
        "trace_id": resp.trace_id,
        "receipt_id": receipt_id,
        "principal": {"type": body.principal.type, "id": body.principal.id},
        "workload": body.workload,
        "action": body.action,
        "destination": body.destination,
        "purpose": body.purpose,
        "session_id": body.session_id,
        "decision": resp.decision.value,
        "reason": [r.value for r in reasons],
        "revocation_epoch": resp.revocation_epoch,
        "policy_version": resp.policy_version,
        "valid_until": receipt.valid_until,
        "request_fingerprint": fp,
        "objects": [
            {"context_id": o.context_id, "version": o.version, "decision": o.decision.value,
             "reason": [r.value for r in o.reason]}
            for o in resp.objects
        ],
        "policy": decided.audit_extra(),
    }
    try:  # fail closed: an unrecorded release decision is not served
        _persist_approval(session, areq, out, ident.subject, now)
        audit_append(session, tenant, ident.subject, "release.authorize", detail, at=now)
        session.add(
            ReleaseReceiptRow(
                receipt_id=receipt_id, tenant_id=tenant, request_fingerprint=fp, decision=resp.decision.value,
                detail=detail, created_at=issued, valid_until=until,
            )
        )
        session.commit()
    except Exception:
        session.rollback()
        raise
    state.metrics.inc("authorize", tenant, resp.decision.value)
    return receipt
