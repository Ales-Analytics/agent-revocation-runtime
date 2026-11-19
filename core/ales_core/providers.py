"""External policy providers (spec v0.4): provider-neutral request/result models and composition.

ALES never translates foreign policy languages: an authoritative engine (OPA, a Cedar service, a custom
HTTP service) is invoked by the server layer and answers ``ALLOW | DENY | UNKNOWN | HUMAN_REVIEW``. This
module is pure (no network, no database writes) so the composition rules are deterministic and unit-testable:

* **Restrict-only AND.** A provider can only make the outcome more restrictive, never override a lineage or
  built-in-policy DENY. The composed decision is the most severe contribution
  (``DECISION_SEVERITY``: ALLOW < HUMAN_REVIEW < UNKNOWN < DENY).
* **Required provider** unavailable (no result, transport error, malformed or already-stale answer) or
  answering ``UNKNOWN`` => ``UNKNOWN`` + ``EXTERNAL_POLICY_UNAVAILABLE`` (fail closed).
* **Optional provider** unavailable or answering ``UNKNOWN`` => recorded and skipped. An explicit optional
  ``DENY`` / ``HUMAN_REVIEW`` still restricts: an answer is an answer, only silence is skippable.
* Provider ``DENY`` => ``DENY`` + ``EXTERNAL_POLICY_DENIED``. ``HUMAN_REVIEW`` => ``HUMAN_REVIEW`` +
  ``POLICY_HUMAN_REVIEW`` and joins the existing approval flow (:func:`apply_composed`).
* Obligations are merged (each tagged with its provider); ``valid_until`` is the minimum over the
  consulted providers. "Not applicable" is a provider-returned ALLOW with no obligations.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from .approvals import ApprovalStore, fingerprint
from .models import (
    DECISION_SEVERITY,
    AuthorizeRequest,
    AuthorizeResponse,
    Decision,
    ObjectVerdict,
    Principal,
    ReasonCode,
)
from .resolver import AuthorizeOutcome, _restrict_deny, _restrict_review, _rfc3339
from .tombstones import utc

PROVIDER_DECISIONS = ("ALLOW", "DENY", "UNKNOWN", "HUMAN_REVIEW")
MAX_OBLIGATIONS = 32
MAX_OBLIGATION_CHARS = 2048
AUDIT_OBLIGATION_CHARS = 200
AUDIT_MAX_OBLIGATIONS = 16

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class ProviderKind(StrEnum):
    OPA = "opa"
    CEDAR = "cedar"
    CUSTOM = "custom"


class ProviderConfig(BaseModel):
    """One configured provider. Secrets are never inline: ``auth_token_env`` names an environment variable."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    url: str
    required: bool = True  # fail closed by default
    kind: ProviderKind = ProviderKind.CUSTOM
    timeout_s: float = Field(default=3.0, gt=0, le=30)
    auth_token_env: str | None = None
    policy_path: str | None = Field(default=None, max_length=512)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not _NAME_RE.match(v):
            raise ValueError("name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
        return v

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        parts = urlsplit(v)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ValueError("url must be an absolute http(s) URL without inline credentials")
        return v

    @field_validator("auth_token_env")
    @classmethod
    def _env(cls, v: str | None) -> str | None:
        if v is not None and not _ENV_RE.match(v):
            raise ValueError("auth_token_env must be an environment variable NAME, never a secret value")
        return v


class ResourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context_id: str
    version: str | None = None
    kind: str | None = None
    classification: str | None = None  # effective (max over lineage), as the policy engine sees it


class PolicyProviderRequest(BaseModel):
    """``{principal, acting_workload, action, resource_refs, purpose, destination, verified_context,
    policy_revision?}``. ``verified_context`` carries only facts ALES itself verified (lineage verdicts,
    effective classification, epoch); it never contains document content."""

    model_config = ConfigDict(extra="forbid")
    principal: Principal
    acting_workload: str | None = None
    action: str
    resource_refs: list[ResourceRef]
    purpose: str
    destination: str | None = None
    verified_context: dict[str, Any] = Field(default_factory=dict)
    policy_revision: str | None = None


def _normalise_instant(v: str) -> str:
    dt = datetime.fromisoformat(v)
    if dt.tzinfo is None:
        raise ValueError("valid_until has no timezone")
    return _rfc3339(dt)


Instant = Annotated[str, AfterValidator(_normalise_instant)]


class PolicyProviderResult(BaseModel):
    """``{decision, obligations?, provider, policy_revision, valid_until?, explanation_ref?}``.

    Types are strict (a provider answering ``"decision": "allow"`` or ``allow: 1`` is malformed, hence
    unavailable); unknown extra fields are ignored so engines may add their own diagnostics.
    ``latency_ms`` is stamped by the caller, never trusted from the wire."""

    model_config = ConfigDict(extra="ignore", strict=True)
    decision: Literal["ALLOW", "DENY", "UNKNOWN", "HUMAN_REVIEW"]
    obligations: list[str | dict[str, Any]] = Field(default_factory=list, max_length=MAX_OBLIGATIONS)
    provider: str = Field(min_length=1, max_length=128)
    policy_revision: str = Field(min_length=1, max_length=256)
    valid_until: Instant | None = None
    explanation_ref: str | None = Field(default=None, max_length=512)
    latency_ms: int | None = None

    @field_validator("obligations")
    @classmethod
    def _bounded(cls, v: list[str | dict[str, Any]]) -> list[str | dict[str, Any]]:
        for o in v:
            if len(json.dumps(o, sort_keys=True, default=str)) > MAX_OBLIGATION_CHARS:
                raise ValueError("obligation too large")
        return v


@dataclass(frozen=True)
class CallMeta:
    """Transport-side facts about one provider call (not part of the provider's answer)."""

    latency_ms: int | None = None
    error: str | None = None  # stable short code: timeout, connect, http_503, malformed, ...


@dataclass(frozen=True)
class ProviderRecord:
    """Audit view of one provider consultation. Identifiers and verdicts only."""

    name: str
    required: bool
    status: str  # "ok" | "unavailable" | "stale" | "ignored" (optional UNKNOWN)
    decision: str | None
    policy_revision: str | None
    latency_ms: int | None
    error: str | None = None
    explanation_ref: str | None = None

    def audit(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "decision": self.decision,
            "policy_revision": self.policy_revision,
            "latency_ms": self.latency_ms,
            "required": self.required,
            "status": self.status,
        }
        if self.error:
            result["error"] = self.error[:64]
        if self.explanation_ref:
            result["explanation_ref"] = self.explanation_ref[:128]
        return result


@dataclass
class ComposedOutcome:
    decision: Decision
    reasons: list[ReasonCode]
    obligations: list[dict[str, Any]] = field(default_factory=list)  # [{"provider", "obligation"}]
    valid_until: str | None = None
    records: list[ProviderRecord] = field(default_factory=list)
    revisions: list[str] = field(default_factory=list)  # "name@revision" of every provider that answered

    def audit_detail(self) -> dict[str, Any]:
        """Identifier-only ledger detail: obligations are clipped JSON strings (never raw nested objects,
        which could carry content-like keys the ledger refuses)."""
        result: dict[str, Any] = {
            "providers": [r.audit() for r in self.records],
            "external_decision": self.decision.value,
        }
        if self.obligations:
            result["obligations"] = [
                json.dumps(o, sort_keys=True, default=str)[:AUDIT_OBLIGATION_CHARS]
                for o in self.obligations[:AUDIT_MAX_OBLIGATIONS]
            ]
        return result


def compose_provider_results(
    results: Sequence[tuple[ProviderConfig, PolicyProviderResult | None]],
    *,
    now: datetime | None = None,
    meta: Mapping[str, CallMeta] | None = None,
) -> ComposedOutcome:
    """Compose provider answers (restrict-only AND). Pure and deterministic.

    ``None`` as a result means the provider was unavailable (transport error, timeout, malformed answer).
    ``now`` (optional) enables the validity check: an answer whose ``valid_until`` is not in the future
    is stale and treated as unavailable. ``meta`` carries per-provider call facts keyed by provider name."""
    meta = meta or {}
    contributions: list[tuple[Decision, ReasonCode]] = []
    records: list[ProviderRecord] = []
    obligations: list[dict[str, Any]] = []
    bounds: list[str] = []
    revisions: list[str] = []
    now_u = utc(now) if now is not None else None

    for configuration, result in results:
        m = meta.get(configuration.name, CallMeta())
        if (
            result is not None
            and now_u is not None
            and result.valid_until is not None
            and datetime.fromisoformat(result.valid_until).astimezone(UTC) <= now_u
        ):
            records.append(
                ProviderRecord(
                    configuration.name,
                    configuration.required,
                    "stale",
                    result.decision,
                    result.policy_revision,
                    result.latency_ms if result.latency_ms is not None else m.latency_ms,
                    "stale_result",
                )
            )
            if configuration.required:
                contributions.append((Decision.UNKNOWN, ReasonCode.EXTERNAL_POLICY_UNAVAILABLE))
            continue
        if result is None:
            records.append(
                ProviderRecord(
                    configuration.name,
                    configuration.required,
                    "unavailable",
                    None,
                    None,
                    m.latency_ms,
                    m.error,
                )
            )
            if configuration.required:
                contributions.append((Decision.UNKNOWN, ReasonCode.EXTERNAL_POLICY_UNAVAILABLE))
            continue

        latency = result.latency_ms if result.latency_ms is not None else m.latency_ms
        revisions.append(f"{configuration.name}@{result.policy_revision}")
        status = "ok"
        if result.decision == "DENY":
            contributions.append((Decision.DENY, ReasonCode.EXTERNAL_POLICY_DENIED))
        elif result.decision == "HUMAN_REVIEW":
            contributions.append((Decision.HUMAN_REVIEW, ReasonCode.POLICY_HUMAN_REVIEW))
        elif result.decision == "UNKNOWN":
            if configuration.required:
                contributions.append((Decision.UNKNOWN, ReasonCode.EXTERNAL_POLICY_UNAVAILABLE))
            else:
                status = "ignored"
        records.append(
            ProviderRecord(
                configuration.name,
                configuration.required,
                status,
                result.decision,
                result.policy_revision,
                latency,
                None,
                result.explanation_ref,
            )
        )
        obligations.extend({"provider": configuration.name, "obligation": o} for o in result.obligations)
        if result.valid_until is not None:
            bounds.append(result.valid_until)

    decision = max((d for d, _ in contributions), key=lambda d: DECISION_SEVERITY[d], default=Decision.ALLOW)
    reasons: list[ReasonCode] = []
    for _, r in contributions:
        if r not in reasons:
            reasons.append(r)
    return ComposedOutcome(
        decision=decision,
        reasons=reasons or [ReasonCode.OK],
        obligations=obligations,
        valid_until=min(bounds) if bounds else None,  # fixed-width UTC strings sort chronologically
        records=records,
        revisions=sorted(revisions),
    )


#: ``action`` sent to providers for a plain ``/v1/authorize`` call (no outward action involved).
AUTHORIZE_ACTION = "context.use"


def build_provider_request(
    request: AuthorizeRequest,
    out: AuthorizeOutcome,
    *,
    action: str | None = None,
    destination: str | None = None,
    policy_revision: str | None = None,
) -> PolicyProviderRequest:
    """Translate the authorize request plus ALES-verified facts into the provider-neutral request."""
    response = out.response
    ctxs = list(out.object_ctx) + [None] * max(0, len(response.objects) - len(out.object_ctx))
    refs = [
        ResourceRef(
            context_id=v.context_id,
            version=v.version,
            kind=c.kind if c is not None else None,
            classification=c.classification if c is not None else None,
        )
        for v, c in zip(response.objects, ctxs, strict=False)
    ]
    verified: dict[str, Any] = {
        "tenant_id": request.tenant_id,
        "revocation_epoch": response.revocation_epoch,
        "policy_version": response.policy_version,
        "ales_decision": response.decision.value,
        "objects": [
            {
                "context_id": v.context_id,
                "version": v.version,
                "decision": v.decision.value,
                "reason": [r.value for r in v.reason],
            }
            for v in response.objects
        ],
        "tools": list(request.tools),
        "risk": request.risk,
        "session_id": request.session_id,
    }
    return PolicyProviderRequest(
        principal=request.principal,
        acting_workload=request.agent_id,
        action=action or AUTHORIZE_ACTION,
        resource_refs=refs,
        purpose=request.purpose,
        destination=destination,
        verified_context=verified,
        policy_revision=policy_revision or response.policy_version,
    )


def needs_provider_call(out: AuthorizeOutcome) -> bool:
    """Providers can only restrict, so nothing at or above UNKNOWN severity can change: skip the calls."""
    return DECISION_SEVERITY[out.response.decision] < DECISION_SEVERITY[Decision.UNKNOWN]


def _restrict_unknown(v: ObjectVerdict, reasons: list[ReasonCode]) -> ObjectVerdict:
    """Fail-closed UNKNOWN. Never loosens: UNKNOWN, QUARANTINE and DENY stand untouched."""
    if DECISION_SEVERITY[v.decision] >= DECISION_SEVERITY[Decision.UNKNOWN]:
        return v
    kept: list[ReasonCode] = [r for r in v.reason if r != ReasonCode.OK]
    for r in reasons:
        if r not in kept:
            kept.append(r)
    return v.model_copy(update={"decision": Decision.UNKNOWN, "reason": kept})


def rebuild_response(resp: AuthorizeResponse, verdicts: list[ObjectVerdict]) -> AuthorizeResponse:
    """Recompute the overall decision/reasons/valid_until from per-object verdicts (same rules as the resolver)."""
    overall = max((v.decision for v in verdicts), key=lambda d: DECISION_SEVERITY[d])
    reasons: list[ReasonCode] = []
    if overall == Decision.ALLOW:
        reasons = [ReasonCode.OK]
    else:
        for v in verdicts:
            if v.decision != Decision.ALLOW:
                for r in v.reason:
                    if r not in reasons:
                        reasons.append(r)
    untils = [v.valid_until for v in verdicts if v.valid_until is not None]
    return resp.model_copy(
        update={
            "decision": overall,
            "reason": reasons,
            "objects": verdicts,
            "valid_until": min(untils) if untils else None,
        }
    )


def apply_composed(
    out: AuthorizeOutcome,
    composed: ComposedOutcome,
    *,
    session: Session,
    request: AuthorizeRequest,
    now: datetime,
    destination: str | None = None,
) -> None:
    """Fold the composed provider outcome into ``out`` (restrict-only; mutates ``out``).

    HUMAN_REVIEW joins the existing approval flow: the fingerprint binds ``(principal, purpose, objects,
    tools, risk, policy_version)`` extended with the consulted provider revisions and the destination, so an
    approval never covers another provider revision or destination. The caller persists the pending record
    (``out.approval_required``) exactly as for built-in policy review."""
    verdicts = list(out.response.objects)
    d = composed.decision
    if d == Decision.DENY:
        verdicts = [_restrict_deny(v, ReasonCode.EXTERNAL_POLICY_DENIED) for v in verdicts]
    elif d == Decision.UNKNOWN:
        verdicts = [_restrict_unknown(v, composed.reasons) for v in verdicts]
    elif d == Decision.HUMAN_REVIEW:
        _external_review(out, verdicts, composed, session, request, now, destination)
    if composed.valid_until is not None:
        for i, v in enumerate(verdicts):
            if v.decision in (Decision.ALLOW, Decision.REFRESH) and (
                v.valid_until is None or composed.valid_until < v.valid_until
            ):
                verdicts[i] = v.model_copy(update={"valid_until": composed.valid_until})
    out.response = rebuild_response(out.response, verdicts)


def _external_review(
    out: AuthorizeOutcome,
    verdicts: list[ObjectVerdict],
    composed: ComposedOutcome,
    session: Session,
    request: AuthorizeRequest,
    now: datetime,
    destination: str | None,
) -> None:
    review_idx = [i for i, v in enumerate(verdicts) if v.decision in (Decision.ALLOW, Decision.REFRESH)]
    if not review_idx:
        return
    objects = sorted({(v.context_id, v.version) for v in verdicts}, key=lambda t: (t[0], t[1] or ""))
    ext_pv = f"{out.response.policy_version}|ext:{','.join(composed.revisions)}|dest:{destination or ''}"
    fp = fingerprint(request.principal, request.purpose, objects, request.tools, request.risk, ext_pv)
    status, record = ApprovalStore.lookup(session, request.tenant_id, fp, now)
    if status == "approved":
        out.fingerprint = fp
        out.approval_id = record.approval_id if record is not None else None
        if record is not None and record.expires_at is not None:
            cap = _rfc3339(record.expires_at)
            for i in review_idx:
                current = verdicts[i].valid_until
                if current is None or cap < current:
                    verdicts[i] = verdicts[i].model_copy(update={"valid_until": cap})
        return
    if status == "denied":
        for i in review_idx:
            verdicts[i] = _restrict_deny(verdicts[i], ReasonCode.APPROVAL_DENIED)
        return
    for i in review_idx:
        verdicts[i] = _restrict_review(
            verdicts[i], [ReasonCode.POLICY_HUMAN_REVIEW, ReasonCode.APPROVAL_PENDING]
        )
    out.approval_required = True
    out.fingerprint = fp
    out.approval_context = {
        "principal": request.principal.model_dump(),  # omits an absent issuer; bound by the fingerprint
        "purpose": request.purpose,
        "objects": [{"context_id": c, "version": version} for c, version in objects],
        "tools": sorted(set(request.tools)),
        "risk": request.risk,
        "policy_version": out.response.policy_version,
        "external": list(composed.revisions),
        "destination": destination,
    }


class ReleaseReceipt(BaseModel):
    """``POST /v1/releases`` answer: short-lived, request-bound. DENY carries ``RELEASE_DENIED`` plus the
    underlying reasons. A receipt bounds, but cannot eliminate, the race to the external side effect."""

    model_config = ConfigDict(extra="forbid")
    receipt_id: str
    decision: Decision
    reason: list[ReasonCode]
    valid_until: str
    revocation_epoch: int = Field(ge=0)
    policy_version: str


def new_receipt_id() -> str:
    return str(uuid.uuid4())


def release_reasons(decision: Decision, underlying: list[ReasonCode]) -> list[ReasonCode]:
    if decision == Decision.ALLOW:
        return [ReasonCode.OK]
    result = [ReasonCode.RELEASE_DENIED]
    result += [r for r in underlying if r not in result and r != ReasonCode.OK]
    return result


def release_capability(action: str) -> str:
    """Capability string a workload needs to perform ``action``: ``action:<action>`` (or the
    ``tool:``-prefixed form, per the existing capability matching convention)."""
    return f"action:{action}"
