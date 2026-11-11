"""ALES INVARIANT core: context integrity and revocation engine."""

from .db import (
    Base,
    ContextObject,
    DerivationEdge,
    InvalidationOutbox,
    RevocationEventRow,
    Tenant,
    create_all,
)
from .exceptions import (
    AlesError,
    AuthorityWidening,
    DuplicateContext,
    InvalidEnvelope,
    LineageIncomplete,
)
from .graph import GraphStore
from .models import (
    AuthorizeRequest,
    AuthorizeResponse,
    Classification,
    ContextEnvelope,
    Decision,
    Kind,
    ObjectRef,
    ObjectVerdict,
    ParentRef,
    Principal,
    ReasonCode,
    RevocationEvent,
    RevocationReason,
    TrustState,
)
from .propagation import EffectiveAuthority, check_not_wider, effective_authority
from .resolver import POLICY_VERSION, authorize
from .revocation import RevocationEngine
from .signing import sign_envelope, sign_event, verify_envelope, verify_event

__all__ = [
    "POLICY_VERSION",
    "AlesError",
    "AuthorityWidening",
    "AuthorizeRequest",
    "AuthorizeResponse",
    "Base",
    "Classification",
    "ContextEnvelope",
    "ContextObject",
    "Decision",
    "DerivationEdge",
    "DuplicateContext",
    "EffectiveAuthority",
    "GraphStore",
    "InvalidEnvelope",
    "InvalidationOutbox",
    "Kind",
    "LineageIncomplete",
    "ObjectRef",
    "ObjectVerdict",
    "ParentRef",
    "Principal",
    "ReasonCode",
    "RevocationEngine",
    "RevocationEvent",
    "RevocationEventRow",
    "RevocationReason",
    "Tenant",
    "TrustState",
    "authorize",
    "check_not_wider",
    "create_all",
    "effective_authority",
    "sign_envelope",
    "sign_event",
    "verify_envelope",
    "verify_event",
]
