"""Deterministic authorization resolver. No LLM, no network; pure function of DB state + now.

Principal matching (v0.5): a principal-scope entry is a bare id (compat), ``iss:<issuer>:<id>`` (only a
principal with that issuer and id) or ``group:<name>`` (any group in ``AuthorizeRequest.groups``); see
:func:`principal_in_scope`. Scopes of different lineage parents still intersect by exact entry, so mixing
spellings across parents can only narrow the result (fail closed). Groups are inputs the server layer
resolves from an entitlement provider; the resolver never fetches them.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .approvals import ApprovalStore, fingerprint
from .db import ContextObject, Tenant, Tombstone
from .graph import GraphStore, Node, find_successors
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
from .tombstones import covers_node, load_tombstones, utc
from .workloads import ENFORCEMENT_MODES, EnforcementMode, WorkloadRegistry, has_capability

POLICY_VERSION = "p0"

Finding = tuple[Decision, ReasonCode]


def _worst(findings: list[Finding]) -> Decision:
    return max(
        (decision for decision, _ in findings), key=DECISION_SEVERITY.__getitem__, default=Decision.ALLOW
    )


def _reasons(findings: list[Finding]) -> list[ReasonCode]:
    return list(dict.fromkeys(reason for _, reason in findings)) or [ReasonCode.OK]


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


def _resolve_version(
    graph: GraphStore, tenant_id: str, ref: ObjectRef, now: datetime
) -> ContextObject | None:
    if ref.version is not None:
        return graph.get_object(tenant_id, ref.context_id, ref.version)
    versions = graph.get_versions(tenant_id, ref.context_id)
    if not versions:
        return None
    # Unversioned reference means "latest": greatest valid_from, ties by version string. A version that
    # is not yet valid (v0.4) is skipped while any currently valid version exists, so a scheduled
    # successor does not shadow the live one before its valid_from.
    valid_versions = [candidate for candidate in versions if utc(candidate.valid_from) <= now]
    return max(
        valid_versions or versions, key=lambda candidate: (candidate.valid_from, candidate.object_version)
    )


def _rfc3339(dt: datetime) -> str:
    return utc(dt).strftime("%Y-%m-%dT%H:%M:%S.%fZ")  # fixed width: strings sort chronologically


#: Reserved scope-entry namespaces (v0.5). An entry starting with one of these is NEVER matched by a bare
#: principal id, so a principal literally named ``group:eng`` or ``iss:x:alice`` cannot impersonate a group
#: or an issuer-qualified identity.
ISSUER_PREFIX = "iss:"
GROUP_PREFIX = "group:"


def qualified_principal(issuer: str, principal_id: str) -> str:
    """The scope-entry spelling of an issuer-qualified principal: ``iss:<issuer>:<id>``."""
    return f"{ISSUER_PREFIX}{issuer}:{principal_id}"


def principal_in_scope(
    scope: Iterable[str], principal_id: str, issuer: str | None = None, groups: Iterable[str] = ()
) -> bool:
    """Does an allow-list (``principal_scope`` / tombstone ``scope_principals``) admit this principal?

    An entry matches when it is
      * the bare id (compat: matches any issuer, and a principal with no issuer; entries in the reserved
        ``iss:`` / ``group:`` namespaces are never matched this way),
      * ``iss:<issuer>:<id>`` (matches only a principal carrying exactly that issuer and id), or
      * ``group:<name>`` for any group the server resolved for the principal.
    An empty scope admits nobody, groups included. Bare entries are the migration path for existing
    deployments; they cannot tell two issuers' "alice" apart, so use ``iss:`` entries for new scopes.
    """
    entries = scope if isinstance(scope, frozenset | set) else frozenset(scope)
    if not entries:
        return False
    if principal_id in entries and not principal_id.startswith((ISSUER_PREFIX, GROUP_PREFIX)):
        return True
    if issuer is not None and qualified_principal(issuer, principal_id) in entries:
        return True
    return any(f"{GROUP_PREFIX}{g}" in entries for g in groups)


def _tomb_applies(t: Tombstone, req: AuthorizeRequest, now: datetime) -> bool:
    """Like ``tombstones.applies`` but with issuer-qualified / group scope entries (restrictive match)."""
    if now < utc(t.effective_at):
        return False
    return _scope_matches(t, req)


def _scope_matches(t: Tombstone, req: AuthorizeRequest) -> bool:
    if t.scope_principals and not principal_in_scope(
        t.scope_principals, req.principal.id, req.principal.issuer, req.groups
    ):
        return False
    return not (t.scope_purposes and req.purpose not in t.scope_purposes)


def _evaluate(
    session: Session, graph: GraphStore, req: AuthorizeRequest, ref: ObjectRef, now: datetime
) -> tuple[ObjectVerdict, ObjectCtx]:
    tenant_id = req.tenant_id
    row = _resolve_version(graph, tenant_id, ref, now)
    if row is None:
        # A foreign-tenant id must be indistinguishable from an unknown one on the wire (no cross-tenant
        # enumeration oracle); the distinction survives only in the audit detail (``tenant_mismatch``).
        foreign = session.scalars(
            select(ContextObject).where(ContextObject.context_id == ref.context_id)
        ).first()
        mismatch = foreign is not None and foreign.tenant_id != tenant_id
        return (
            ObjectVerdict(
                context_id=ref.context_id,
                version=ref.version,
                decision=Decision.UNKNOWN,
                reason=[ReasonCode.OBJECT_UNKNOWN],
            ),
            ObjectCtx(tenant_mismatch=mismatch),
        )

    nodes: list[Node] = [(row.context_id, row.object_version)]
    nodes += graph.get_ancestors(tenant_id, row.context_id, row.object_version)
    loaded = graph.load_objects(tenant_id, nodes)
    findings: list[Finding] = []
    if any(node not in loaded for node in nodes):
        # An edge points at a node that does not exist for this tenant: the stored lineage is corrupt
        # (registration refuses missing parents), so the verdict is UNKNOWN with the distinct
        # LINEAGE_UNCERTAIN reason; LINEAGE_INCOMPLETE is kept alongside for existing consumers.
        findings.append((Decision.UNKNOWN, ReasonCode.LINEAGE_INCOMPLETE))
        findings.append((Decision.UNKNOWN, ReasonCode.LINEAGE_UNCERTAIN))

    lineage_objects = [loaded[node] for node in nodes if node in loaded]
    # Tombstones are authoritative (effective_at + scope). A pending (future) or non-matching
    # (other principal/purpose) tombstone contributes nothing, so it can never surface as a deny.
    tombstones = load_tombstones(session, tenant_id, {node[0] for node in nodes})
    active_tombstones = [tombstone for tombstone in tombstones if _tomb_applies(tombstone, req, now)]

    def covered(cid: str, ver: str) -> bool:
        return any(covers_node(tombstone, cid, ver) for tombstone in active_tombstones)

    # REFRESH is decided per tombstone *and* covered node: a superseded node is refreshable only when
    # that same object has a live (non-covered) sibling version to re-derive from. A superseded ancestor
    # with no live successor stays DENY, whatever happens elsewhere in the lineage.
    def has_live_sibling(cid: str, ver: str) -> bool:
        if any(
            v.object_version != ver and not covered(v.context_id, v.object_version)
            for v in graph.get_versions(tenant_id, cid)
        ):
            return True
        # v0.4: a replacement registered under a NEW context_id (successor_of) counts too.
        successors = find_successors(session, tenant_id, cid, ver)
        if not successors:
            return False
        # Successors live outside this lineage, so their tombstones were not loaded above.
        successor_tombstones = [
            tombstone
            for tombstone in load_tombstones(session, tenant_id, {c for c, _ in successors})
            if _tomb_applies(tombstone, req, now)
        ]
        return any(
            not covered(c, v) and not any(covers_node(tombstone, c, v) for tombstone in successor_tombstones)
            for c, v in successors
        )

    for node in nodes:
        for tombstone in active_tombstones:
            if covers_node(tombstone, node[0], node[1]):
                refreshable = tombstone.reason == RevocationReason.VERSION_SUPERSEDED and has_live_sibling(
                    node[0], node[1]
                )
                findings.append(_tombstone_finding(tombstone.reason, refreshable))
    for lineage_object in lineage_objects:
        if lineage_object.expires_at is not None and utc(lineage_object.expires_at) <= now:
            findings.append((Decision.DENY, ReasonCode.ANCESTOR_EXPIRED))
        if utc(lineage_object.valid_from) > now:
            findings.append((Decision.DENY, ReasonCode.NOT_YET_VALID))

    authority = effective_authority(lineage_objects)
    if authority.principal_scope is not None and not principal_in_scope(
        authority.principal_scope, req.principal.id, req.principal.issuer, req.groups
    ):
        findings.append((Decision.DENY, ReasonCode.PRINCIPAL_NOT_IN_SCOPE))
    if authority.purpose_scope is not None and req.purpose not in authority.purpose_scope:
        findings.append((Decision.DENY, ReasonCode.PURPOSE_NOT_IN_SCOPE))
    if authority.trust_state == TrustState.QUARANTINED:
        findings.append((Decision.QUARANTINE, ReasonCode.ANCESTOR_QUARANTINED))

    # A verdict computed now can change at the earliest pending effective_at (no epoch bump happens then).
    pending = [
        utc(tombstone.effective_at)
        for tombstone in tombstones
        if utc(tombstone.effective_at) > now
        and _scope_matches(tombstone, req)
        and any(covers_node(tombstone, c, v) for c, v in nodes)
    ]
    # Validity bound: earliest of pending tombstone effective_at and any ancestor (or own) future expiry.
    bounds = list(pending) + [
        utc(lineage_object.expires_at)
        for lineage_object in lineage_objects
        if lineage_object.expires_at is not None and utc(lineage_object.expires_at) > now
    ]
    verdict = ObjectVerdict(
        context_id=row.context_id,
        version=row.object_version,
        decision=_worst(findings),
        reason=_reasons(findings),
        valid_until=_rfc3339(min(bounds)) if bounds else None,
    )
    # Policy sees the *effective* classification (max over the whole lineage), never less than the
    # object's own: a derivative of a restricted source is restricted for policy purposes too.
    return verdict, ObjectCtx(kind=row.kind, classification=authority.classification.value)


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
    tenant_mismatch: bool = False  # a requested id exists in another tenant (wire verdict is OBJECT_UNKNOWN)
    object_ctx: list[ObjectCtx] = field(
        default_factory=list
    )  # per-object kind/effective classification (v0.4)

    def audit_extra(self) -> dict[str, Any]:
        """Identifier-only detail for ``audit.record_decision(..., extra=...)``."""
        details: dict[str, Any] = {"workload_gate": self.workload_gate}
        if self.workload_enforcement != "auto":
            details["workload_enforcement"] = self.workload_enforcement
        if self.grant_missing:
            details["grant_missing"] = True
        if self.tenant_mismatch:
            details["tenant_mismatch"] = True
        if self.policy_rule_id is not None:
            details["policy_rule_id"] = self.policy_rule_id
        if self.approval_id is not None:
            details["approval_id"] = self.approval_id
        if self.fingerprint is not None:
            details["fingerprint"] = self.fingerprint
        return details


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
    policy_result = evaluate_policy(
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
    out.policy_rule_id = policy_result.rule_id
    review_indexes: list[int] = []
    for index, object_policy in enumerate(policy_result.per_object):
        if object_policy.effect == Effect.DENY:
            verdicts[index] = _restrict_deny(verdicts[index], ReasonCode.POLICY_DENIED)
        elif object_policy.effect == Effect.HUMAN_REVIEW:
            review_indexes.append(index)
    if policy_result.require_fresh_lineage:
        # Obligation: incomplete/unknown lineage is a hard DENY for the whole request, even for public data.
        for index, verdict in enumerate(verdicts):
            if verdict.decision == Decision.UNKNOWN:
                verdicts[index] = _restrict_deny(verdict, ReasonCode.POLICY_DENIED)
    review_indexes = [
        index for index in review_indexes if verdicts[index].decision in (Decision.ALLOW, Decision.REFRESH)
    ]
    if not review_indexes:
        return
    object_versions = sorted(
        {(verdict.context_id, verdict.version) for verdict in verdicts}, key=lambda t: (t[0], t[1] or "")
    )
    request_fingerprint = fingerprint(
        request.principal, request.purpose, object_versions, request.tools, request.risk, policy_version
    )
    out.fingerprint = request_fingerprint
    status, approval = ApprovalStore.lookup(session, request.tenant_id, request_fingerprint, now)
    if status == "approved":
        out.approval_id = approval.approval_id if approval is not None else None
        if approval is not None and approval.expires_at is not None:
            # The honoured approval lapses at expires_at: a cached ALLOW must not outlive it.
            approval_deadline = _rfc3339(approval.expires_at)
            for index in review_indexes:
                current_deadline = verdicts[index].valid_until
                if current_deadline is None or approval_deadline < current_deadline:
                    verdicts[index] = verdicts[index].model_copy(update={"valid_until": approval_deadline})
        return  # unexpired approval for this exact fingerprint: proceed as lineage decided
    if status == "denied":
        for index in review_indexes:
            verdicts[index] = _restrict_deny(verdicts[index], ReasonCode.APPROVAL_DENIED)
        return
    for index in review_indexes:
        verdicts[index] = _restrict_review(
            verdicts[index], [ReasonCode.POLICY_HUMAN_REVIEW, ReasonCode.APPROVAL_PENDING]
        )
    out.approval_required = True
    out.approval_context = {
        "principal": request.principal.model_dump(),  # omits an absent issuer; bound by the fingerprint
        "purpose": request.purpose,
        "objects": [{"context_id": c, "version": version} for c, version in object_versions],
        "tools": sorted(set(request.tools)),
        "risk": request.risk,
        "policy_version": policy_version,
        "rule_id": policy_result.rule_id,
    }


def _apply_workload_gate(
    session: Session,
    request: AuthorizeRequest,
    verdicts: list[ObjectVerdict],
    enforcement: EnforcementMode,
    require_grants: bool,
) -> tuple[list[ObjectVerdict], bool, bool]:
    """Apply workload restrictions and return verdicts, gate status, and missing-grant status."""
    if not request.agent_id or enforcement == "off":
        return verdicts, False, False
    tenant_id = request.tenant_id
    gate_enabled = enforcement == "strict" or WorkloadRegistry.has_any(session, tenant_id)
    if not gate_enabled:
        return verdicts, False, False

    workload = WorkloadRegistry.get(session, tenant_id, request.agent_id)
    grant_missing = False
    if workload is None or workload.status != "active":
        reason = ReasonCode.WORKLOAD_SUSPENDED
    elif any(not has_capability(list(workload.capabilities or []), tool) for tool in request.tools):
        reason = ReasonCode.CAPABILITY_MISSING
    elif (
        require_grants or WorkloadRegistry.has_any_grants(session, tenant_id)
    ) and not WorkloadRegistry.can_act_as(session, tenant_id, request.principal.id, request.agent_id):
        grant_missing = True
        reason = ReasonCode.PRINCIPAL_NOT_IN_SCOPE
    else:
        return verdicts, True, False
    return [_restrict_deny(verdict, reason) for verdict in verdicts], True, grant_missing


def authorize_ex(
    session: Session,
    request: AuthorizeRequest,
    now: datetime,
    *,
    enforce_workloads: EnforcementMode = "auto",
    require_grants: bool = False,
) -> AuthorizeOutcome:
    """Lineage -> workload gate -> policy (restrict-only) -> approvals. Read-only on the database.

    ``enforce_workloads``: ``"auto"`` (default; gate on once the tenant has any workload), ``"strict"``
    (requests with an ``agent_id`` are always checked) or ``"off"`` (no workload/grant checks). Any other
    value raises ``ValueError`` (fail closed rather than silently weaken the gate).

    ``require_grants``: when True and the workload gate is on for the request, a principal must hold a
    grant for the agent even if the tenant has no grant rows at all, so deleting the last grant cannot
    switch the grants gate off. Default False keeps the opt-in behaviour."""
    if enforce_workloads not in ENFORCEMENT_MODES:
        raise ValueError(f"enforce_workloads must be one of {ENFORCEMENT_MODES}, got {enforce_workloads!r}")
    now = utc(now)
    graph = GraphStore(session)
    tenant_id = request.tenant_id
    # Read the epoch before lineage so concurrent revocation cannot give old data a newer epoch.
    # Query the column directly to bypass SQLAlchemy's identity map.
    epoch_at_start = session.scalar(select(Tenant.revocation_epoch).where(Tenant.tenant_id == tenant_id)) or 0
    evaluated = [_evaluate(session, graph, request, ref, now) for ref in request.objects]
    verdicts = [evaluation[0] for evaluation in evaluated]
    object_contexts = [evaluation[1] for evaluation in evaluated]

    verdicts, gate, grant_missing = _apply_workload_gate(
        session, request, verdicts, enforce_workloads, require_grants
    )

    policy_document = PolicyStore.get_active(session, tenant_id)
    policy_version = policy_document.policy_version if policy_document is not None else POLICY_VERSION
    outcome = AuthorizeOutcome(
        response=None,  # type: ignore[arg-type]  # set below
        workload_gate=gate,
        grant_missing=grant_missing,
        workload_enforcement=enforce_workloads,
        tenant_mismatch=any(context.tenant_mismatch for context in object_contexts),
        object_ctx=list(object_contexts),
    )  # type: ignore[arg-type]  # set below
    if policy_document is not None:
        _apply_policy(
            session, request, policy_document, verdicts, object_contexts, policy_version, now, outcome
        )

    overall = max(
        (object_verdict.decision for object_verdict in verdicts), key=lambda d: DECISION_SEVERITY[d]
    )
    if overall == Decision.ALLOW:
        reasons = [ReasonCode.OK]
    else:
        reasons = list(
            dict.fromkeys(
                reason
                for verdict in verdicts
                if verdict.decision != Decision.ALLOW
                for reason in verdict.reason
            )
        )
    validity_deadlines = [
        object_verdict.valid_until for object_verdict in verdicts if object_verdict.valid_until is not None
    ]
    outcome.response = AuthorizeResponse(
        decision=overall,
        reason=reasons,
        revocation_epoch=epoch_at_start,
        policy_version=policy_version,
        trace_id=str(uuid.uuid4()),
        objects=verdicts,
        valid_until=min(validity_deadlines)
        if validity_deadlines
        else None,  # fixed-format UTC strings sort chronologically
    )
    return outcome


def authorize(
    session: Session,
    request: AuthorizeRequest,
    now: datetime,
    *,
    enforce_workloads: EnforcementMode = "auto",
    require_grants: bool = False,
) -> AuthorizeResponse:
    """Decision only. Servers that need audit extras / approval creation use :func:`authorize_ex`."""
    return authorize_ex(
        session, request, now, enforce_workloads=enforce_workloads, require_grants=require_grants
    ).response
