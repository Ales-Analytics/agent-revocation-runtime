"""Ed25519 signing of envelopes and revocation events over RFC 8785 (JCS) canonical JSON.

The signed payload is the object minus ``signature`` and ``issuer_key_id``. Keys are always
passed in; trust in a key (who is allowed to sign for a tenant) is the job of ``keys.py``.

Canonicalisation is delegated to the ``rfc8785`` package (ECMAScript number serialisation,
UTF-16 code-unit key ordering, minimal string escaping). Models are signed in their full JSON
form, i.e. optional members that are null are present as ``null``.
"""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from enum import Enum
from typing import Any, TypeVar

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel

from .exceptions import CanonicalizationError

#: Members never covered by the signature.
UNSIGNED_FIELDS: tuple[str, ...] = ("signature", "issuer_key_id")

M = TypeVar("M", bound=BaseModel)


def _jsonable(value: Any) -> Any:
    """Reduce arbitrary input to JSON types, mirroring pydantic's ``mode='json'`` output."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        v = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return v.isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return _jsonable(value.value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _as_dict(obj: Any) -> dict[str, Any]:
    out = _jsonable(obj)
    if not isinstance(out, dict):
        raise CanonicalizationError("signable object must be a mapping or model")
    return out


def canonicalize(value: Any) -> bytes:
    """RFC 8785 canonical JSON of an arbitrary JSON-compatible value (UTF-8 bytes)."""
    try:
        return rfc8785.dumps(_jsonable(value))
    except (rfc8785.CanonicalizationError, TypeError, ValueError, OverflowError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def canonical_bytes(obj: Any) -> bytes:
    """Bytes that are signed: JCS of the object without ``signature`` and ``issuer_key_id``."""
    d = _as_dict(obj)
    for f in UNSIGNED_FIELDS:
        d.pop(f, None)
    # v0.4 additive member: a null/absent ``successor_of`` is not part of the signed form, so envelopes
    # signed before the field existed (or by clients that do not know it) still verify.
    if d.get("successor_of") is None:
        d.pop("successor_of", None)
    return canonicalize(d)


def _sign(obj: Any, private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(private_key.sign(canonical_bytes(obj))).decode("ascii")


def _verify(obj: Any, public_key: Ed25519PublicKey) -> bool:
    try:
        sig = _as_dict(obj).get("signature")
        if not sig or not isinstance(sig, str):
            return False
        public_key.verify(base64.b64decode(sig, validate=True), canonical_bytes(obj))
    except (InvalidSignature, binascii.Error, ValueError, CanonicalizationError):
        return False
    return True


def sign_envelope(env: Any, private_key: Ed25519PrivateKey) -> str:
    return _sign(env, private_key)


def verify_envelope(env: Any, public_key: Ed25519PublicKey) -> bool:
    return _verify(env, public_key)


def sign_event(event: Any, private_key: Ed25519PrivateKey) -> str:
    return _sign(event, private_key)


def verify_event(event: Any, public_key: Ed25519PublicKey) -> bool:
    return _verify(event, public_key)


def sign_model(model: M, private_key: Ed25519PrivateKey, issuer_key_id: str) -> M:
    """Return a copy of an envelope/event stamped with ``issuer_key_id`` and its signature."""
    sig = _sign(model, private_key)
    return model.model_copy(update={"signature": sig, "issuer_key_id": issuer_key_id})
