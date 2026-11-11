"""Pydantic models mirroring the v0.1 spec schemas."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator


def _aware(v: datetime | None) -> datetime | None:
    if v is None:
        return None
    if v.tzinfo is None:
        return v.replace(tzinfo=UTC)
    return v.astimezone(UTC)


def _uuid_str(v: str) -> str:
    uuid.UUID(v)
    return v


AwareDT = Annotated[datetime, AfterValidator(_aware)]
UuidStr = Annotated[str, AfterValidator(_uuid_str)]


class Kind(StrEnum):
    SOURCE = "source"
    CHUNK = "chunk"
    EMBEDDING = "embedding"
    SUMMARY = "summary"
    MEMORY = "memory"
    CACHE = "cache"
    ARTIFACT = "artifact"


class Classification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return _CLASS_RANK[self.value]


class TrustState(StrEnum):
    VERIFIED = "verified"
    UNTRUSTED = "untrusted"
    QUARANTINED = "quarantined"

    @property
    def rank(self) -> int:
        return _TRUST_RANK[self.value]


_CLASS_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
_TRUST_RANK = {"verified": 0, "untrusted": 1, "quarantined": 2}


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"
    REFRESH = "REFRESH"
    REDACT = "REDACT"
    QUARANTINE = "QUARANTINE"
    HUMAN_REVIEW = "HUMAN_REVIEW"


# Severity order: ALLOW < REFRESH < HUMAN_REVIEW < REDACT < UNKNOWN < QUARANTINE < DENY
DECISION_SEVERITY: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.REFRESH: 1,
    Decision.HUMAN_REVIEW: 2,
    Decision.REDACT: 3,
    Decision.UNKNOWN: 4,
    Decision.QUARANTINE: 5,
    Decision.DENY: 6,
}


class ReasonCode(StrEnum):
    ANCESTOR_ACL_REVOKED = "ANCESTOR_ACL_REVOKED"
    ANCESTOR_DELETED = "ANCESTOR_DELETED"
    ANCESTOR_SUPERSEDED = "ANCESTOR_SUPERSEDED"
    ANCESTOR_EXPIRED = "ANCESTOR_EXPIRED"
    ANCESTOR_QUARANTINED = "ANCESTOR_QUARANTINED"
    PRINCIPAL_NOT_IN_SCOPE = "PRINCIPAL_NOT_IN_SCOPE"
    PURPOSE_NOT_IN_SCOPE = "PURPOSE_NOT_IN_SCOPE"
    LINEAGE_INCOMPLETE = "LINEAGE_INCOMPLETE"
    OBJECT_UNKNOWN = "OBJECT_UNKNOWN"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    POLICY_SNAPSHOT_STALE = "POLICY_SNAPSHOT_STALE"
    OK = "OK"


class RevocationReason(StrEnum):
    DELETED = "deleted"
    ACL_CHANGED = "acl_changed"
    VERSION_SUPERSEDED = "version_superseded"
    EXPIRED = "expired"
    COMPROMISED = "compromised"
    POISONED = "poisoned"


class ParentRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context_id: UuidStr
    object_version: str


class ContextEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    context_id: UuidStr
    tenant_id: str = Field(min_length=1)
    object_id: str = Field(min_length=1)
    object_version: str = Field(min_length=1)
    content_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    kind: Kind
    source_system: str
    source_acl_ref: str | None = None
    principal_scope: list[str] = Field(default_factory=list)
    purpose_scope: list[str] = Field(default_factory=list)
    classification: Classification
    trust_state: TrustState
    parent_refs: list[ParentRef]
    policy_version: str
    valid_from: AwareDT
    expires_at: AwareDT | None = None
    signature: str | None = None

    @model_validator(mode="after")
    def _check_parents(self) -> ContextEnvelope:
        if self.kind == Kind.SOURCE and self.parent_refs:
            raise ValueError("source envelopes must not have parent_refs")
        if self.kind != Kind.SOURCE and not self.parent_refs:
            raise ValueError("non-source envelopes require at least one parent_ref")
        return self


class AffectedScope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principals: list[str] | None = None
    purposes: list[str] | None = None


class RevocationEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UuidStr
    tenant_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    source_version: str | None = None
    reason: RevocationReason
    effective_at: AwareDT
    source_event_id: str | None = None
    actor: str | None = None
    affected_scope: AffectedScope | None = None
    signature: str | None = None


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(pattern=r"^(user|agent|service)$")
    id: str


class ObjectRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context_id: str
    version: str | None = None


class AuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str
    principal: Principal
    purpose: str
    agent_id: str | None = None
    session_id: str | None = None
    objects: list[ObjectRef] = Field(min_length=1)


class ObjectVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context_id: str
    version: str | None = None
    decision: Decision
    reason: list[ReasonCode]


class AuthorizeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Decision
    reason: list[ReasonCode]
    revocation_epoch: int = Field(ge=0)
    policy_version: str
    trace_id: str
    objects: list[ObjectVerdict]
