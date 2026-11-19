"""Deterministic policy engine (spec v0.3 "Policy engine").

A tenant may install a versioned :class:`PolicyDocument`. Exactly one document version is *active*
per tenant. No LLM, no I/O, no clock: :func:`evaluate_policy` is a pure function of ``(doc, ctx)``.

Semantics (normative for this implementation)
---------------------------------------------
* **Pairs.** A request is evaluated per ``(object, tool)`` pair: every object in ``ctx.objects`` is
  crossed with every tool in ``ctx.tools`` (an empty side contributes a single ``None``). Each pair is
  resolved *first-match in document order* against the rules, falling back to ``default_action``. Pair
  effects are aggregated worst-wins (``deny`` > ``human_review`` > ``allow``). Evaluating per pair (not
  per request) closes the "padding" bypass where an extra benign object or tool would make a
  selector-scoped deny rule stop matching.
* **Selectors.** An absent selector matches everything. A present selector is a non-empty list of
  exact strings, or ``"*"`` which matches any *present* value. Neither an exact string nor ``"*"`` matches
  an absent value (e.g. ``agent_id=None``); to cover absent values, omit the selector. ``resources.kinds`` / ``classifications`` are matched
  against the pair's object; ``resources.tools`` against the pair's tool; ``risk`` is an *exact*
  match on the caller-asserted risk (a rule with ``risk`` never matches a request that omits ``risk``).
  A resource selector never matches the ``None`` side (no object / no tool / unresolved object).
* **Risk floors.** ``risk`` is caller-asserted and therefore advisory: a caller could *lower* it to dodge a
  rule keyed on a higher risk. ``PolicyDocument.risk_floors`` (``{purpose or "*": low|medium|high}``) is
  the trusted server-side control. The effective risk used for ``Rule.risk`` matching is
  ``max(caller risk, floors[purpose], floors["*"])`` with ``low < medium < high``; an absent caller risk
  counts as the floor itself. With no applicable floor the caller's value (or absence) is used unchanged.
  An unrecognised caller risk string is ignored once a floor applies. Floors only ever raise the risk.
* **Obligations** apply to the matched rule of a pair regardless of its effect:

  - ``max_classification``: if the pair's object classification is *above* it, the pair effect becomes
    ``deny`` (reason ``POLICY_DENIED``). An object whose classification is unknown (unresolved) is
    left to lineage evaluation (it is UNKNOWN there already).
  - ``require_fresh_lineage``: recorded as ``PolicyOutcome.require_fresh_lineage``. The resolver then
    converts UNKNOWN lineage (``OBJECT_UNKNOWN`` / ``LINEAGE_INCOMPLETE``) into DENY +
    ``POLICY_DENIED`` for the whole request *even when the data is public*. It does NOT deny
    REFRESH-able (superseded-with-live-successor) objects and changes nothing for objects whose lineage
    is complete.
* **Restrict only.** Policy never loosens a lineage verdict (see ``resolver``); a rule ``allow`` means
  "no additional restriction".
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .db import PolicyDocumentRow, lock_tenant, utcnow
from .exceptions import AlesError
from .models import AwareDT, Classification, ReasonCode

WILDCARD = "*"


class PolicyError(AlesError):
    """Invalid policy install/activate (non-monotonic version, unknown document, tenant mismatch)."""


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    HUMAN_REVIEW = "human_review"


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_EFFECT_RANK = {Effect.ALLOW: 0, Effect.HUMAN_REVIEW: 1, Effect.DENY: 2}
_RISK_RANK = {Risk.LOW: 0, Risk.MEDIUM: 1, Risk.HIGH: 2}


def _selector(v: list[str] | None) -> list[str] | None:
    if v is None:
        return None
    if not v:
        # An empty selector is ambiguous (match nothing? everything?). Refuse rather than guess.
        raise ValueError("selector lists must be non-empty (omit the selector to match all)")
    if any((not isinstance(x, str)) or not x for x in v):
        raise ValueError("selector entries must be non-empty strings")
    return list(v)


Selector = Annotated[list[str] | None, AfterValidator(_selector)]


class SubjectSelector(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principals: Selector = None
    principal_types: Selector = None
    agents: Selector = None


class ResourceSelector(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kinds: Selector = None
    classifications: Selector = None
    tools: Selector = None

    @field_validator("classifications")
    @classmethod
    def _valid_classes(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            valid = {c.value for c in Classification} | {WILDCARD}
            bad = [x for x in v if x not in valid]
            if bad:
                raise ValueError(f"unknown classification(s): {bad}")
        return v


class Obligations(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_classification: Classification | None = None
    require_fresh_lineage: bool = False


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(min_length=1)
    effect: Effect
    subjects: SubjectSelector | None = None
    resources: ResourceSelector | None = None
    purposes: Selector = None
    risk: Risk | None = None
    obligations: Obligations | None = None


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    version: int = Field(ge=1)
    rules: list[Rule] = Field(default_factory=list)
    default_action: Effect = Effect.DENY  # fail closed when omitted
    risk_floors: dict[str, Risk] = Field(default_factory=dict)  # purpose or "*" -> minimum effective risk
    created_by: str = Field(min_length=1)
    created_at: AwareDT = Field(default_factory=utcnow)

    @field_validator("policy_id")
    @classmethod
    def _no_at(cls, v: str) -> str:
        if "@" in v:
            raise ValueError("policy_id must not contain '@' (it is the policy_version separator)")
        return v

    @field_validator("risk_floors")
    @classmethod
    def _floor_keys(cls, v: dict[str, Risk]) -> dict[str, Risk]:
        if any((not isinstance(k, str)) or not k.strip() or k != k.strip() for k in v):
            raise ValueError('risk_floors keys must be non-empty purposes (no surrounding whitespace) or "*"')
        return v

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> PolicyDocument:
        rule_counts = Counter(rule.rule_id for rule in self.rules)
        duplicates = sorted(rule_id for rule_id, count in rule_counts.items() if count > 1)
        if duplicates:
            raise ValueError(f"duplicate rule_id(s): {duplicates}")
        return self

    @property
    def policy_version(self) -> str:
        return policy_version_string(self.policy_id, self.version)


def policy_version_string(policy_id: str, version: int) -> str:
    return f"{policy_id}@{version}"


class ObjectCtx(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str | None = None  # None = unresolved object
    classification: str | None = None
    tenant_mismatch: bool = (
        False  # audit-only: the reference exists in another tenant (wire verdict is UNKNOWN)
    )


class PolicyContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principal_id: str
    principal_type: str = "user"
    agent_id: str | None = None
    purpose: str
    objects: list[ObjectCtx] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    risk: str | None = None


class PairOutcome(BaseModel):
    """Policy result for one object position (worst over that object's tools)."""

    model_config = ConfigDict(frozen=True)
    effect: Effect
    rule_id: str | None
    reasons: tuple[ReasonCode, ...]


class PolicyOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)
    effect: Effect
    rule_id: str | None  # rule that produced the (worst) effect; None when default_action applied
    reasons: tuple[ReasonCode, ...]
    require_fresh_lineage: bool = False
    # One entry per ctx.objects position, in order (a ctx without objects yields one entry).
    per_object: tuple[PairOutcome, ...] = ()


def _match(selector: Sequence[str] | None, value: str | None) -> bool:
    if selector is None:
        return True
    if value is None:
        return False  # "*" means "any value that is present"; omit the selector to match absent values too
    return WILDCARD in selector or value in selector


def _rule_matches(rule: Rule, ctx: PolicyContext, obj: ObjectCtx | None, tool: str | None) -> bool:
    s = rule.subjects
    if s is not None and not (
        _match(s.principals, ctx.principal_id)
        and _match(s.principal_types, ctx.principal_type)
        and _match(s.agents, ctx.agent_id)
    ):
        return False
    r = rule.resources
    if r is not None and not (
        _match(r.kinds, obj.kind if obj else None)
        and _match(r.classifications, obj.classification if obj else None)
        and _match(r.tools, tool)
    ):
        return False
    if not _match(rule.purposes, ctx.purpose):
        return False
    return not (rule.risk is not None and ctx.risk != rule.risk.value)


def _reasons_for(effect: Effect) -> tuple[ReasonCode, ...]:
    if effect == Effect.DENY:
        return (ReasonCode.POLICY_DENIED,)
    if effect == Effect.HUMAN_REVIEW:
        return (ReasonCode.POLICY_HUMAN_REVIEW,)
    return (ReasonCode.OK,)


def _class_rank(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return Classification(value).rank
    except ValueError:
        return Classification.RESTRICTED.rank + 1  # unknown label: treat as above everything (fail closed)


def _eval_pair(
    doc: PolicyDocument, ctx: PolicyContext, obj: ObjectCtx | None, tool: str | None
) -> tuple[Effect, str | None, bool]:
    for rule in doc.rules:
        if not _rule_matches(rule, ctx, obj, tool):
            continue
        effect = rule.effect
        fresh = False
        ob = rule.obligations
        if ob is not None:
            fresh = ob.require_fresh_lineage
            if ob.max_classification is not None and obj is not None:
                rank = _class_rank(obj.classification)
                if rank is not None and rank > ob.max_classification.rank:
                    effect = Effect.DENY
        return effect, rule.rule_id, fresh
    return doc.default_action, None, False


def effective_risk(doc: PolicyDocument, purpose: str, caller_risk: str | None) -> str | None:
    """``max(caller risk, floor[purpose], floor["*"])``; the caller's value unchanged when no floor applies."""
    floors = [doc.risk_floors[k] for k in (purpose, WILDCARD) if k in doc.risk_floors]
    if not floors:
        return caller_risk
    best = max(floors, key=lambda r: _RISK_RANK[r])
    try:
        caller = Risk(caller_risk) if caller_risk is not None else None
    except ValueError:
        caller = None  # unrecognised label: cannot outrank a floor
    if caller is not None and _RISK_RANK[caller] > _RISK_RANK[best]:
        best = caller
    return best.value


def evaluate_policy(doc: PolicyDocument, ctx: PolicyContext | dict) -> PolicyOutcome:
    """Evaluate ``doc`` against ``ctx``; pure and deterministic (see module docstring)."""
    if not isinstance(ctx, PolicyContext):
        ctx = PolicyContext.model_validate(ctx)
    risk = effective_risk(doc, ctx.purpose, ctx.risk)
    if risk != ctx.risk:
        ctx = ctx.model_copy(update={"risk": risk})
    objects: list[ObjectCtx | None] = list(ctx.objects) or [None]
    tools: list[str | None] = list(ctx.tools) or [None]
    per_object: list[PairOutcome] = []
    fresh_any = False
    worst: tuple[Effect, str | None] | None = None
    for obj in objects:
        o_worst: tuple[Effect, str | None] | None = None
        for tool in tools:
            effect, rule_id, fresh = _eval_pair(doc, ctx, obj, tool)
            fresh_any = fresh_any or fresh
            if o_worst is None or _EFFECT_RANK[effect] > _EFFECT_RANK[o_worst[0]]:
                o_worst = (effect, rule_id)
        assert o_worst is not None
        per_object.append(
            PairOutcome(effect=o_worst[0], rule_id=o_worst[1], reasons=_reasons_for(o_worst[0]))
        )
        if worst is None or _EFFECT_RANK[o_worst[0]] > _EFFECT_RANK[worst[0]]:
            worst = o_worst
    assert worst is not None
    return PolicyOutcome(
        effect=worst[0],
        rule_id=worst[1],
        reasons=_reasons_for(worst[0]),
        require_fresh_lineage=fresh_any,
        per_object=tuple(per_object),
    )


class PolicyStore:
    """Versioned policy documents; one active document version per tenant.

    All mutators take the tenant lock (:func:`ales_core.db.lock_tenant`) so install/activate for a
    tenant serialise, and never commit: the caller owns the transaction (an exception rolls back both
    the swap and its audit record together).
    """

    @staticmethod
    def install(session: Session, doc: PolicyDocument) -> PolicyDocumentRow:
        """Store a new (inactive) version. ``doc.version`` must exceed every existing version of
        ``doc.policy_id`` for the tenant (monotonic; re-installing or going backwards is refused)."""
        lock_tenant(session, doc.tenant_id)
        latest = session.scalars(
            select(PolicyDocumentRow.version)
            .where(PolicyDocumentRow.tenant_id == doc.tenant_id, PolicyDocumentRow.policy_id == doc.policy_id)
            .order_by(PolicyDocumentRow.version.desc())
            .limit(1)
        ).first()
        if latest is not None and doc.version <= latest:
            raise PolicyError(
                f"policy {doc.policy_id!r} version {doc.version} must be greater than existing version {latest}"
            )
        row = PolicyDocumentRow(
            tenant_id=doc.tenant_id,
            policy_id=doc.policy_id,
            version=doc.version,
            document=doc.model_dump(mode="json"),
            active=False,
            created_by=doc.created_by,
            created_at=doc.created_at,
        )
        session.add(row)
        session.flush()
        audit.append(
            session,
            doc.tenant_id,
            doc.created_by,
            "policy.install",
            {"policy_id": doc.policy_id, "version": doc.version, "rules": len(doc.rules)},
        )
        return row

    @staticmethod
    def activate(
        session: Session,
        tenant: str,
        policy_id: str,
        version: int,
        *,
        actor: str,
        at: datetime | None = None,
    ) -> PolicyDocumentRow:
        """Atomically make ``(policy_id, version)`` the tenant's only active document (rollback to an
        older installed version is allowed) and append a ``policy.activate`` audit record."""
        lock_tenant(session, tenant)
        target = session.scalars(
            select(PolicyDocumentRow).where(
                PolicyDocumentRow.tenant_id == tenant,
                PolicyDocumentRow.policy_id == policy_id,
                PolicyDocumentRow.version == version,
            )
        ).first()
        if target is None:
            raise PolicyError(f"policy {policy_id!r} version {version} is not installed for tenant")
        previous = None
        for row in session.scalars(
            select(PolicyDocumentRow).where(
                PolicyDocumentRow.tenant_id == tenant, PolicyDocumentRow.active.is_(True)
            )
        ):
            if row.id != target.id:
                previous = policy_version_string(row.policy_id, row.version)
                row.active = False
        target.active = True
        session.flush()
        audit.append(
            session,
            tenant,
            actor,
            "policy.activate",
            {"policy_id": policy_id, "version": version, "previous": previous},
            at=at,
        )
        return target

    @staticmethod
    def get_active(session: Session, tenant: str) -> PolicyDocument | None:
        rows = session.scalars(
            select(PolicyDocumentRow)
            .where(PolicyDocumentRow.tenant_id == tenant, PolicyDocumentRow.active.is_(True))
            .order_by(PolicyDocumentRow.id.desc())
        ).all()
        if not rows:
            return None
        # Defensive: the invariant is "at most one"; if it were ever violated, use the newest row
        # deterministically rather than failing open or crashing the decision path.
        return PolicyDocument.model_validate(rows[0].document)

    @staticmethod
    def list_versions(
        session: Session, tenant: str, policy_id: str | None = None
    ) -> list[tuple[str, int, bool]]:
        """``[(policy_id, version, active), ...]`` ordered by policy_id then version."""
        statement = select(PolicyDocumentRow).where(PolicyDocumentRow.tenant_id == tenant)
        if policy_id is not None:
            statement = statement.where(PolicyDocumentRow.policy_id == policy_id)
        statement = statement.order_by(PolicyDocumentRow.policy_id, PolicyDocumentRow.version)
        return [(r.policy_id, r.version, r.active) for r in session.scalars(statement)]

    @staticmethod
    def get(session: Session, tenant: str, policy_id: str, version: int) -> PolicyDocument | None:
        row = session.scalars(
            select(PolicyDocumentRow).where(
                PolicyDocumentRow.tenant_id == tenant,
                PolicyDocumentRow.policy_id == policy_id,
                PolicyDocumentRow.version == version,
            )
        ).first()
        return PolicyDocument.model_validate(row.document) if row else None
