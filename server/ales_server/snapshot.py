"""Signed policy snapshots (SPEC v0.2). Mirrors the contract in ``ales_sdk.snapshot`` exactly.

Signed object: ``{tenant_id, revocation_epoch, policy_version, issued_at, lease_seconds}``
(all integers are plain ints, ``issued_at`` is RFC 3339 with an explicit UTC offset). The signature is
Ed25519 over the RFC 8785 canonical bytes of that object (``signature``/``key_id`` are never signed),
returned base64 (standard, padded) next to a ``key_id`` that identifies the signing key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .config import ConfigError

log = logging.getLogger("ales.server.snapshot")

UNSIGNED_FIELDS = ("signature", "key_id")


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    obj = {k: v for k, v in payload.items() if k not in UNSIGNED_FIELDS}
    for v in obj.values():
        if isinstance(v, float | bool):
            raise TypeError("floats/bools are not permitted in a signed snapshot")
    return rfc8785.dumps(obj)


def _decode_seed(value: str | bytes | Ed25519PrivateKey) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    raw: bytes
    if isinstance(value, bytes) and len(value) == 32:
        raw = value
    else:
        text = value.decode("ascii", "strict") if isinstance(value, bytes) else value
        text = text.strip()
        pad = "=" * (-len(text) % 4)
        try:
            raw = (
                base64.urlsafe_b64decode(text + pad)
                if ("-" in text or "_" in text)
                else base64.b64decode(text + pad, validate=True)
            )
        except (binascii.Error, ValueError, UnicodeError) as exc:
            raise ConfigError("snapshot key is not valid base64") from exc
    if len(raw) != 32:
        raise ConfigError(f"snapshot key must be a base64 raw 32-byte Ed25519 seed, got {len(raw)} bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


class SnapshotSigner:
    def __init__(self, key: Ed25519PrivateKey, *, ephemeral: bool, key_id: str | None = None):
        self._key = key
        self.ephemeral = ephemeral
        raw_pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_key_b64 = base64.b64encode(raw_pub).decode("ascii")
        self.key_id = key_id or "snap-" + hashlib.sha256(raw_pub).hexdigest()[:12]

    @classmethod
    def load(cls, configured: str | bytes | Ed25519PrivateKey | None, key_id: str | None = None) -> SnapshotSigner:
        """Use the configured key; with none configured generate an ephemeral dev key (loud warning).

        A configured-but-malformed key is a startup error, never a silent fallback to ephemeral.
        """
        if configured is None or (isinstance(configured, str) and not configured.strip()):
            log.warning(
                "ALES_SNAPSHOT_KEY not set: using an EPHEMERAL snapshot signing key. Clients must fetch its "
                "public key from GET /v1/snapshot/public_key and it changes on every restart. Dev only."
            )
            return cls(Ed25519PrivateKey.generate(), ephemeral=True, key_id=key_id)
        return cls(_decode_seed(configured), ephemeral=False, key_id=key_id)

    def sign(self, tenant_id: str, revocation_epoch: int, policy_version: str, lease_seconds: int) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "tenant_id": tenant_id,
            "revocation_epoch": int(revocation_epoch),
            "policy_version": policy_version,
            "issued_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "lease_seconds": int(lease_seconds),
        }
        sig = self._key.sign(canonical_bytes(payload))
        return {**payload, "signature": base64.b64encode(sig).decode("ascii"), "key_id": self.key_id}
