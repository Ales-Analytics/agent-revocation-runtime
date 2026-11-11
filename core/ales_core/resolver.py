"""Deterministic authorization resolver. No LLM, no network; pure function of DB state + now."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import ContextObject, Tenant
from .graph import GraphStore, Node
from .models import (
    DECISION_SEVERITY,
    AuthorizeRequest,
    AuthorizeResponse,
    Decision,
    ObjectRef,
    ObjectVerdict,
    ReasonCode,
    RevocationReason,
    TrustState,
)
from .propagation import effective_authority

POLICY_VERSION = "p0"

Finding = tuple[Decision, ReasonCode]


def _worst(findings: list[Finding]) -> Decision:
    if not findings:
        return Decision.ALLOW
    return max((f[0] for f in findings), key=lambda d: DECISION_SEVERITY[d])


def _reasons(findings: list[Finding]) -> list[ReasonCode]:
    seen: list[ReasonCode] = []
    for _, r in findings:
        if r not in seen:
            seen.append(r)
    return seen or [ReasonCode.OK]


def _tombstone_finding(row: ContextObject, refreshable: bool) -> Finding:
    reason = row.tombstone_reason
    if reason == RevocationReason.DELETED:
        return Decision.DENY, ReasonCode.ANCESTOR_DELETED
    if reason == RevocationReason.ACL_CHANGED:
        return Decision.DENY, ReasonCode.ANCESTOR_ACL_REVOKED
    if reason == RevocationReason.VERSION_SUPERSEDED:
        if refreshable:
            return Decision.REFRESH, ReasonCode.ANCESTOR_SUPERSEDED
        return Decision.DENY, ReasonCode.ANCESTOR_SUPERSEDED
    if reason == RevocationReason.EXPIRED:
        return Decision.DENY, ReasonCode.ANCESTOR_EXPIRED
    if reason in (RevocationReason.COMPROMISED, RevocationReason.POISONED):
        return Decision.QUARANTINE, ReasonCode.ANCESTOR_QUARANTINED
    # Unrecognised tombstone reason: fail closed.
    return Decision.DENY, ReasonCode.ANCESTOR_DELETED


def _resolve_version(graph: GraphStore, tenant_id: str, ref: ObjectRef) -> ContextObject | None:
    if ref.version is not None:
        return graph.get_object(tenant_id, ref.context_id, ref.version)
    versions = graph.get_versions(tenant_id, ref.context_id)
    if not versions:
        return None
    # Unversioned reference means "latest": greatest valid_from, ties by version string.
    return max(versions, key=lambda r: (r.valid_from, r.object_version))


def _evaluate(
    session: Session, graph: GraphStore, req: AuthorizeRequest, ref: ObjectRef, now: datetime
) -> ObjectVerdict:
    tenant_id = req.tenant_id
    row = _resolve_version(graph, tenant_id, ref)
    if row is None:
        # Distinguish cross-tenant from truly unknown.
        foreign = session.scalars(
            select(ContextObject).where(ContextObject.context_id == ref.context_id)
        ).first()
        if foreign is not None and foreign.tenant_id != tenant_id:
            return ObjectVerdict(
                context_id=ref.context_id,
                version=ref.version,
                decision=Decision.DENY,
                reason=[ReasonCode.TENANT_MISMATCH],
            )
        return ObjectVerdict(
            context_id=ref.context_id,
            version=ref.version,
            decision=Decision.UNKNOWN,
            reason=[ReasonCode.OBJECT_UNKNOWN],
        )

    nodes: list[Node] = [(row.context_id, row.object_version)]
    nodes += graph.get_ancestors(tenant_id, row.context_id, row.object_version)
    loaded = graph.load_objects(tenant_id, nodes)
    findings: list[Finding] = []

    if any(n not in loaded for n in nodes):
        findings.append((Decision.UNKNOWN, ReasonCode.LINEAGE_INCOMPLETE))

    objs = [loaded[n] for n in nodes if n in loaded]
    # REFRESH is possible when a superseded object in the lineage has a live newer version
    # (descendants are tombstoned with the same reason, but the fix is re-deriving from the new parent).
    refreshable = any(
        o.tombstoned
        and o.tombstone_reason == RevocationReason.VERSION_SUPERSEDED
        and any(
            v.object_version != o.object_version and not v.tombstoned
            for v in graph.get_versions(tenant_id, o.context_id)
        )
        for o in objs
    )
    for o in objs:
        if o.tombstoned:
            findings.append(_tombstone_finding(o, refreshable))
        if o.expires_at is not None and o.expires_at <= now:
            findings.append((Decision.DENY, ReasonCode.ANCESTOR_EXPIRED))

    eff = effective_authority(objs)
    if eff.principal_scope is not None and req.principal.id not in eff.principal_scope:
        findings.append((Decision.DENY, ReasonCode.PRINCIPAL_NOT_IN_SCOPE))
    if eff.purpose_scope is not None and req.purpose not in eff.purpose_scope:
        findings.append((Decision.DENY, ReasonCode.PURPOSE_NOT_IN_SCOPE))
    if eff.trust_state == TrustState.QUARANTINED:
        findings.append((Decision.QUARANTINE, ReasonCode.ANCESTOR_QUARANTINED))

    return ObjectVerdict(
        context_id=row.context_id,
        version=row.object_version,
        decision=_worst(findings),
        reason=_reasons(findings),
    )


def authorize(session: Session, request: AuthorizeRequest, now: datetime) -> AuthorizeResponse:
    graph = GraphStore(session)
    verdicts = [_evaluate(session, graph, request, ref, now) for ref in request.objects]
    overall = max((v.decision for v in verdicts), key=lambda d: DECISION_SEVERITY[d])
    if overall == Decision.ALLOW:
        reasons = [ReasonCode.OK]
    else:
        reasons = []
        for v in verdicts:
            if v.decision != Decision.ALLOW:
                for r in v.reason:
                    if r not in reasons:
                        reasons.append(r)
    tenant = session.get(Tenant, request.tenant_id)
    return AuthorizeResponse(
        decision=overall,
        reason=reasons,
        revocation_epoch=tenant.revocation_epoch if tenant else 0,
        policy_version=POLICY_VERSION,
        trace_id=str(uuid.uuid4()),
        objects=verdicts,
    )
