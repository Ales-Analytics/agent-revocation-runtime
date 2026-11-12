"""Deterministic authorization resolver. No LLM, no network; pure function of DB state + now."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import ContextObject, Tenant, Tombstone
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
from .tombstones import applies, covers_node, load_tombstones, utc

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


def _tombstone_finding(reason: str, refreshable: bool) -> Finding:
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


def _superseding(live: list[Tombstone], o: ContextObject) -> bool:
    return any(
        t.reason == RevocationReason.VERSION_SUPERSEDED and covers_node(t, o.context_id, o.object_version)
        for t in live
    )


def _rfc3339(dt: datetime) -> str:
    return utc(dt).strftime("%Y-%m-%dT%H:%M:%S.%fZ")  # fixed width: strings sort chronologically


def _scope_matches(t: Tombstone, principal_id: str, purpose: str) -> bool:
    if t.scope_principals and principal_id not in t.scope_principals:
        return False
    return not (t.scope_purposes and purpose not in t.scope_purposes)


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
    principal_id, purpose = req.principal.id, req.purpose

    if any(n not in loaded for n in nodes):
        findings.append((Decision.UNKNOWN, ReasonCode.LINEAGE_INCOMPLETE))

    objs = [loaded[n] for n in nodes if n in loaded]
    # Tombstones are authoritative (effective_at + scope). A pending (future) or non-matching
    # (other principal/purpose) tombstone contributes nothing, so it can never surface as a deny.
    tombs = load_tombstones(session, tenant_id, {n[0] for n in nodes})
    live = [t for t in tombs if applies(t, principal_id, purpose, now)]

    def covered(cid: str, ver: str) -> bool:
        return any(covers_node(t, cid, ver) for t in live)

    # REFRESH is possible when a superseded object in the lineage has a sibling version that
    # is still usable for this request (the fix is re-deriving from the new parent).
    refreshable = any(
        _superseding(live, o) and any(
            v.object_version != o.object_version and not covered(v.context_id, v.object_version)
            for v in graph.get_versions(tenant_id, o.context_id)
        )
        for o in objs
    )
    for n in nodes:
        for t in live:
            if covers_node(t, n[0], n[1]):
                findings.append(_tombstone_finding(t.reason, refreshable))
    for o in objs:
        if o.expires_at is not None and o.expires_at <= now:
            findings.append((Decision.DENY, ReasonCode.ANCESTOR_EXPIRED))

    eff = effective_authority(objs)
    if eff.principal_scope is not None and req.principal.id not in eff.principal_scope:
        findings.append((Decision.DENY, ReasonCode.PRINCIPAL_NOT_IN_SCOPE))
    if eff.purpose_scope is not None and req.purpose not in eff.purpose_scope:
        findings.append((Decision.DENY, ReasonCode.PURPOSE_NOT_IN_SCOPE))
    if eff.trust_state == TrustState.QUARANTINED:
        findings.append((Decision.QUARANTINE, ReasonCode.ANCESTOR_QUARANTINED))

    # A verdict computed now can change at the earliest pending effective_at (no epoch bump happens then).
    pending = [
        utc(t.effective_at)
        for t in tombs
        if utc(t.effective_at) > now
        and _scope_matches(t, principal_id, purpose)
        and any(covers_node(t, c, v) for c, v in nodes)
    ]
    return ObjectVerdict(
        context_id=row.context_id,
        version=row.object_version,
        decision=_worst(findings),
        reason=_reasons(findings),
        valid_until=_rfc3339(min(pending)) if pending else None,
    )


def authorize(session: Session, request: AuthorizeRequest, now: datetime) -> AuthorizeResponse:
    now = utc(now)
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
    untils = [v.valid_until for v in verdicts if v.valid_until is not None]
    tenant = session.get(Tenant, request.tenant_id)
    return AuthorizeResponse(
        decision=overall,
        reason=reasons,
        revocation_epoch=tenant.revocation_epoch if tenant else 0,
        policy_version=POLICY_VERSION,
        trace_id=str(uuid.uuid4()),
        objects=verdicts,
        valid_until=min(untils) if untils else None,  # fixed-format UTC strings sort chronologically
    )
