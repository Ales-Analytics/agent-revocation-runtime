"""Trusted-issuer key registry and registry-backed signature verification.

Only a key registered *for the object's tenant* and currently ``active`` may vouch for an
envelope or revocation event. ``verify_with_registry`` is a pure function of DB state.

Status lifecycle (forward only): ``active -> retired -> revoked`` (``active -> revoked`` is also
allowed). Retired and revoked keys are both rejected for new objects (``key_not_active``);
``revoked`` is terminal.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import ContextObject, IssuerKey
from .exceptions import CanonicalizationError, KeyRegistryError
from .signing import canonical_bytes


class KeyStatus(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class VerifyReason(StrEnum):
    MISSING_SIGNATURE = "missing_signature"
    UNKNOWN_KEY = "unknown_key"
    KEY_NOT_ACTIVE = "key_not_active"
    BAD_SIGNATURE = "bad_signature"
    CROSS_TENANT_KEY = "cross_tenant_key"
    OK = "ok"


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: str
    key_id: str | None = None

    def __bool__(self) -> bool:  # an accidental `if result:` must not be a silent always-true
        return self.ok


_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "active": {"retired", "revoked"},
    "retired": {"revoked"},
    "revoked": set(),
}


def _public_key_b64(public_key: Ed25519PublicKey | bytes | str) -> str:
    if isinstance(public_key, Ed25519PublicKey):
        raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    elif isinstance(public_key, bytes):
        raw = public_key
    elif isinstance(public_key, str):
        try:
            raw = base64.b64decode(public_key, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise KeyRegistryError("public key is not valid base64") from exc
    else:
        raise KeyRegistryError("unsupported public key type")
    if len(raw) != 32:
        raise KeyRegistryError("Ed25519 public key must be 32 raw bytes")
    return base64.b64encode(raw).decode("ascii")


class KeyRegistry:
    """Thin DB facade; every method takes the session and never commits (caller owns the tx)."""

    def __init__(self, session: Session):
        self.session = session

    def register_key(
        self,
        tenant_id: str,
        key_id: str,
        public_key: Ed25519PublicKey | bytes | str,
        status: str = "active",
    ) -> IssuerKey:
        if not tenant_id or not key_id:
            raise KeyRegistryError("tenant_id and key_id are required")
        try:
            KeyStatus(status)
        except ValueError as exc:
            raise KeyRegistryError(f"invalid status {status!r}") from exc
        b64 = _public_key_b64(public_key)
        if self.session.get(IssuerKey, key_id) is not None:
            # key_ids are global and immutable: no re-binding, even for the owning tenant.
            raise KeyRegistryError(f"key_id {key_id!r} already registered")
        row = IssuerKey(key_id=key_id, tenant_id=tenant_id, public_key_b64=b64, status=status)
        self.session.add(row)
        self.session.flush()
        return row

    def set_status(self, tenant_id: str, key_id: str, status: str) -> IssuerKey:
        try:
            new = KeyStatus(status).value
        except ValueError as exc:
            raise KeyRegistryError(f"invalid status {status!r}") from exc
        row = self.session.get(IssuerKey, key_id)
        if row is None or row.tenant_id != tenant_id:
            raise KeyRegistryError(f"unknown key {key_id!r} for tenant")
        if row.status == new:
            return row
        if new not in _ALLOWED_TRANSITIONS.get(row.status, set()):
            raise KeyRegistryError(f"illegal key status transition {row.status} -> {new}")
        row.status = new
        self.session.flush()
        return row

    def get_active(self, tenant_id: str, key_id: str) -> IssuerKey | None:
        row = self.session.get(IssuerKey, key_id)
        if row is None or row.tenant_id != tenant_id or row.status != KeyStatus.ACTIVE.value:
            return None
        return row

    def get(self, key_id: str) -> IssuerKey | None:
        return self.session.get(IssuerKey, key_id)


def _field(obj: Any, name: str) -> Any:
    if isinstance(obj, BaseModel):
        return getattr(obj, name, None)
    return obj.get(name) if isinstance(obj, dict) else None


def verify_with_registry(session: Session, obj: Any) -> VerifyResult:
    """Verify an envelope/event against the tenant's trusted-issuer registry.

    Check order is fixed so the reason is deterministic: missing signature, unknown key,
    cross-tenant key, key not active, bad signature. Cross-tenant is checked before status so
    another tenant's key lifecycle is never revealed.
    """
    signature = _field(obj, "signature")
    if not signature or not isinstance(signature, str):
        return VerifyResult(False, VerifyReason.MISSING_SIGNATURE.value)
    key_id = _field(obj, "issuer_key_id")
    if not key_id or not isinstance(key_id, str):
        return VerifyResult(False, VerifyReason.UNKNOWN_KEY.value)
    row = session.get(IssuerKey, key_id)
    if row is None:
        return VerifyResult(False, VerifyReason.UNKNOWN_KEY.value, key_id)
    tenant_id = _field(obj, "tenant_id")
    if not tenant_id or row.tenant_id != tenant_id:
        return VerifyResult(False, VerifyReason.CROSS_TENANT_KEY.value, key_id)
    if row.status != KeyStatus.ACTIVE.value:
        return VerifyResult(False, VerifyReason.KEY_NOT_ACTIVE.value, key_id)
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(row.public_key_b64))
        pub.verify(base64.b64decode(signature, validate=True), canonical_bytes(obj))
    except (InvalidSignature, binascii.Error, ValueError, CanonicalizationError):
        return VerifyResult(False, VerifyReason.BAD_SIGNATURE.value, key_id)
    return VerifyResult(True, VerifyReason.OK.value, key_id)


# ------------------------------------------------------------------ compromise workflow (v0.4)
#: Fixed namespace so event ids derived from (key, context_id, version) are stable across runs/processes.
_KEY_COMPROMISE_NS = uuid.UUID("6f0c1d2e-8a4b-5c7d-9e3f-0a1b2c3d4e5f")


def affected_sources(
    session: Session, tenant_id: str, key_id: str, *, include_derived: bool = False
) -> list[tuple[str, str]]:
    """``(context_id, version)`` of the tenant's objects signed by ``key_id``, sorted.

    Only ``kind == source`` by default; ``include_derived=True`` also returns derived objects the key
    signed (their tombstones then cover their own descendants)."""
    stmt = select(ContextObject.context_id, ContextObject.object_version).where(
        ContextObject.tenant_id == tenant_id, ContextObject.issuer_key_id == key_id
    )
    if not include_derived:
        stmt = stmt.where(ContextObject.kind == "source")
    return sorted((r[0], r[1]) for r in session.execute(stmt))


def compromise_event_id(key_id: str, context_id: str, version: str) -> str:
    return str(uuid.uuid5(_KEY_COMPROMISE_NS, f"{key_id}\x00{context_id}\x00{version}"))


def revoke_sources_for_key(
    session: Session,
    tenant_id: str,
    key_id: str,
    *,
    actor: str,
    reason: str = "compromised",
    now: datetime,
    include_derived: bool = False,
) -> list[str]:
    """Emit one revocation event per object the compromised key signed (sources by default).

    Event ids are deterministic (uuid5 of key+context+version), so re-running is idempotent: existing
    events are returned as-is and nothing new is recorded. Descendants are denied through the normal
    tombstone lineage walk. Commits (via the revocation engine) and appends one audit record."""
    from . import audit
    from .models import RevocationEvent, RevocationReason
    from .revocation import RevocationEngine

    try:
        rev_reason = RevocationReason(reason)
    except ValueError as exc:
        raise KeyRegistryError(f"invalid revocation reason {reason!r}") from exc
    targets = affected_sources(session, tenant_id, key_id, include_derived=include_derived)
    engine = RevocationEngine()
    ids: list[str] = []
    for cid, ver in targets:
        ev = RevocationEvent(
            event_id=compromise_event_id(key_id, cid, ver),
            tenant_id=tenant_id,
            source_id=cid,
            source_version=ver,
            reason=rev_reason,
            effective_at=now,
            actor=actor,
        )
        engine.accept(session, ev, now=now, actor=actor)
        ids.append(ev.event_id)
    audit.append(
        session,
        tenant_id,
        actor,
        "key.revoke_sources",
        {"key_id": key_id[:255], "reason": reason, "objects": len(ids), "event_ids": ids[:100]},
        at=now,
    )
    session.commit()
    return ids
