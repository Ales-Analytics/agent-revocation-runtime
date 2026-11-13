"""Deterministic authorization resolver. No LLM, no network; pure function of DB state + now."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .approvals import ApprovalStore, fingerprint
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
from .policy import Effect, ObjectCtx, PolicyContext, PolicyDocument, PolicyStore, evaluate_policy
from .propagation import effective_authority
from .tombstones import applies, covers_node, load_tombstones, utc
from .workloads import ENFORCEMENT_MODES, EnforcementMode, WorkloadRegistry, has_capability

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
) -> tuple[ObjectVerdict, ObjectCtx]:
    tenant_id = req.tenant_id
    row = _resolve_version(graph, tenant_id, ref)
    if row is None:
        # Distinguish cross-tenant from truly unknown.
        foreign = session.scalars(
            select(ContextObject).where(ContextObject.context_id == ref.context_id)
        ).first()
        if foreign is not None and foreign.tenant_id != tenant_id:
            return (
                ObjectVerdict(
                    context_id=ref.context_id,
                    version=ref.version,
                    decision=Decision.DENY,
                    reason=[ReasonCode.TENANT_MISMATCH],
                ),
                ObjectCtx(),
            )
        return (
            ObjectVerdict(
                context_id=ref.context_id,
                version=ref.version,
                decision=Decision.UNKNOWN,
                reason=[ReasonCode.OBJECT_UNKNOWN],
            ),
            ObjectCtx(),
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
    verdict = ObjectVerdict(
        context_id=row.context_id,
        version=row.object_version,
        decision=_worst(findings),
        reason=_reasons(findings),
        valid_until=_rfc3339(min(pending)) if pending else None,
    )
    # Policy sees the *effective* classification (max over the whole lineage), never less than the
    # object's own: a derivative of a restricted source is restricted for policy purposes too.
    return verdict, ObjectCtx(kind=row.kind, classification=eff.classification.value)


@dataclass
class AuthorizeOutcome:
    """Decision plus the side information the server layer needs (audit detail, approval creation).

    The resolver stays read-only: when ``approval_required`` is set the server must call
    ``ApprovalStore.ensure_pending(session, tenant, fingerprint, approval_context)``.
    """

    response: AuthorizeResponse
    policy_rule_id: str | None = None
    approval_id: str | None = None  # an unexpired approved record that was honoured
    approval_required: bool = False
    fingerprint: str | None = None
    approval_context: dict[str, Any] | None = None
    workload_gate: bool = False  # agent_id/tools were enforced (auto: tenant has workloads; strict: always)
    grant_missing: bool = False  # the grants gate is on and the principal holds no grant for the agent
    workload_enforcement: str = "auto"

    def audit_extra(self) -> dict[str, Any]:
        """Identifier-only detail for ``audit.record_decision(..., extra=...)``."""
        out: dict[str, Any] = {"workload_gate": self.workload_gate}
        if self.workload_enforcement != "auto":
            out["workload_enforcement"] = self.workload_enforcement
        if self.grant_missing:
            out["grant_missing"] = True
        if self.policy_rule_id is not None:
            out["policy_rule_id"] = self.policy_rule_id
        if self.approval_id is not None:
            out["approval_id"] = self.approval_id
        if self.fingerprint is not None:
            out["fingerprint"] = self.fingerprint
        return out


def _restrict_deny(v: ObjectVerdict, reason: ReasonCode) -> ObjectVerdict:
    """Policy/workload deny. Never loosens: DENY and QUARANTINE stand untouched; every lower-severity
    verdict (ALLOW, REFRESH, REDACT, UNKNOWN) becomes DENY with the original reasons kept."""
    if v.decision in (Decision.DENY, Decision.QUARANTINE):
        return v
    kept: list[ReasonCode] = [r for r in v.reason if r != ReasonCode.OK]
    if reason not in kept:
        kept.append(reason)
    return v.model_copy(update={"decision": Decision.DENY, "reason": kept})


def _restrict_review(v: ObjectVerdict, reasons: list[ReasonCode]) -> ObjectVerdict:
    if v.decision not in (Decision.ALLOW, Decision.REFRESH):
        return v  # anything already at/above HUMAN_REVIEW severity stands
    kept: list[ReasonCode] = [r for r in v.reason if r != ReasonCode.OK]
    for r in reasons:
        if r not in kept:
            kept.append(r)
    return v.model_copy(update={"decision": Decision.HUMAN_REVIEW, "reason": kept})


def _apply_policy(
    session: Session,
    request: AuthorizeRequest,
    doc: PolicyDocument,
    verdicts: list[ObjectVerdict],
    octx: list[ObjectCtx],
    policy_version: str,
    now: datetime,
    out: AuthorizeOutcome,
) -> None:
    pol = evaluate_policy(
        doc,
        PolicyContext(
            principal_id=request.principal.id,
            principal_type=request.principal.type,
            agent_id=request.agent_id,
            purpose=request.purpose,
            objects=octx,
            tools=list(request.tools),
            risk=request.risk,
        ),
    )
    out.policy_rule_id = pol.rule_id
    review_idx: list[int] = []
    for i, po in enumerate(pol.per_object):
        if po.effect == Effect.DENY:
            verdicts[i] = _restrict_deny(verdicts[i], ReasonCode.POLICY_DENIED)
        elif po.effect == Effect.HUMAN_REVIEW:
            review_idx.append(i)
    if pol.require_fresh_lineage:
        # Obligation: incomplete/unknown lineage is a hard DENY for the whole request, even for public data.
        for i, v in enumerate(verdicts):
            if v.decision == Decision.UNKNOWN:
                verdicts[i] = _restrict_deny(v, ReasonCode.POLICY_DENIED)
    review_idx = [i for i in review_idx if verdicts[i].decision in (Decision.ALLOW, Decision.REFRESH)]
    if not review_idx:
        return
    objs = sorted({(v.context_id, v.version) for v in verdicts}, key=lambda t: (t[0], t[1] or ""))
    fp = fingerprint(request.principal, request.purpose, objs, policy_version)
    out.fingerprint = fp
    status, rec = ApprovalStore.lookup(session, request.tenant_id, fp, now)
    if status == "approved":
        out.approval_id = rec.approval_id if rec is not None else None
        return  # unexpired approval for this exact fingerprint: proceed as lineage decided
    if status == "denied":
        for i in review_idx:
            verdicts[i] = _restrict_deny(verdicts[i], ReasonCode.APPROVAL_DENIED)
        return
    for i in review_idx:
        verdicts[i] = _restrict_review(verdicts[i], [ReasonCode.POLICY_HUMAN_REVIEW, ReasonCode.APPROVAL_PENDING])
    out.approval_required = True
    out.approval_context = {
        "principal": {"type": request.principal.type, "id": request.principal.id},
        "purpose": request.purpose,
        "objects": [{"context_id": c, "version": ver} for c, ver in objs],
        "policy_version": policy_version,
        "rule_id": pol.rule_id,
    }


def authorize_ex(
    session: Session, request: AuthorizeRequest, now: datetime, *, enforce_workloads: EnforcementMode = "auto"
) -> AuthorizeOutcome:
    """Lineage -> workload gate -> policy (restrict-only) -> approvals. Read-only on the database.

    ``enforce_workloads``: ``"auto"`` (default; gate on once the tenant has any workload), ``"strict"``
    (requests with an ``agent_id`` are always checked) or ``"off"`` (no workload/grant checks). Any other
    value raises ``ValueError`` (fail closed rather than silently weaken the gate)."""
    if enforce_workloads not in ENFORCEMENT_MODES:
        raise ValueError(f"enforce_workloads must be one of {ENFORCEMENT_MODES}, got {enforce_workloads!r}")
    now = utc(now)
    graph = GraphStore(session)
    tenant_id = request.tenant_id
    evaluated = [_evaluate(session, graph, request, ref, now) for ref in request.objects]
    verdicts = [e[0] for e in evaluated]
    octx = [e[1] for e in evaluated]

    # Workload identity gate. ``auto``: enforced only for tenants with >= 1 registered workload; ``strict``:
    # always; ``off``: never. Only requests that name an agent_id are checked. Unknown == suspended.
    gate = False
    grant_missing = False
    if request.agent_id and enforce_workloads != "off":
        gate = enforce_workloads == "strict" or WorkloadRegistry.has_any(session, tenant_id)
    if gate and request.agent_id is not None:
        wl = WorkloadRegistry.get(session, tenant_id, request.agent_id)
        if wl is None or wl.status != "active":
            verdicts = [_restrict_deny(v, ReasonCode.WORKLOAD_SUSPENDED) for v in verdicts]
        elif any(not has_capability(list(wl.capabilities or []), t) for t in request.tools):
            verdicts = [_restrict_deny(v, ReasonCode.CAPABILITY_MISSING) for v in verdicts]
        elif WorkloadRegistry.has_any_grants(session, tenant_id) and not WorkloadRegistry.can_act_as(
            session, tenant_id, request.principal.id, request.agent_id
        ):
            # Second opt-in gate: once the tenant records any grant, acting as an agent needs one.
            grant_missing = True
            verdicts = [_restrict_deny(v, ReasonCode.PRINCIPAL_NOT_IN_SCOPE) for v in verdicts]

    doc = PolicyStore.get_active(session, tenant_id)
    policy_version = doc.policy_version if doc is not None else POLICY_VERSION
    out = AuthorizeOutcome(
        response=None,  # type: ignore[arg-type]  # set below
        workload_gate=gate,
        grant_missing=grant_missing,
        workload_enforcement=enforce_workloads,
    )  # type: ignore[arg-type]  # set below
    if doc is not None:
        _apply_policy(session, request, doc, verdicts, octx, policy_version, now, out)

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
    tenant = session.get(Tenant, tenant_id)
    out.response = AuthorizeResponse(
        decision=overall,
        reason=reasons,
        revocation_epoch=tenant.revocation_epoch if tenant else 0,
        policy_version=policy_version,
        trace_id=str(uuid.uuid4()),
        objects=verdicts,
        valid_until=min(untils) if untils else None,  # fixed-format UTC strings sort chronologically
    )
    return out


def authorize(
    session: Session, request: AuthorizeRequest, now: datetime, *, enforce_workloads: EnforcementMode = "auto"
) -> AuthorizeResponse:
    """Decision only. Servers that need audit extras / approval creation use :func:`authorize_ex`."""
    return authorize_ex(session, request, now, enforce_workloads=enforce_workloads).response
