"""Ed25519 signing of envelopes and revocation events. Keys are always passed in."""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel


def _as_dict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    return dict(obj)


def canonical_bytes(obj: Any) -> bytes:
    d = _as_dict(obj)
    d.pop("signature", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sign(obj: Any, private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(private_key.sign(canonical_bytes(obj))).decode("ascii")


def _verify(obj: Any, public_key: Ed25519PublicKey) -> bool:
    sig = _as_dict(obj).get("signature")
    if not sig:
        return False
    try:
        public_key.verify(base64.b64decode(sig, validate=True), canonical_bytes(obj))
    except (InvalidSignature, ValueError):
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
