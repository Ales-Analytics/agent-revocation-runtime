"""Signed policy snapshot verification (SPEC v0.2, "Signed policy snapshots and offline operation").

Wire contract (the server MUST mirror this exactly)
---------------------------------------------------
``GET /v1/snapshot`` (bearer-authenticated, ``read`` role) returns a JSON object::

    {
      "tenant_id":        str,   # must equal the caller's tenant
      "revocation_epoch": int,   # >= 0, no floats
      "policy_version":   str,
      "issued_at":        str,   # RFC 3339 timestamp with timezone, e.g. "2026-01-01T00:00:00Z"
      "lease_seconds":    int,   # > 0, no floats
      "signature":        str,   # base64 (standard or url-safe, padding optional) of 64-byte Ed25519 sig
      "key_id":           str    # optional; selects the verification key when several are configured
    }

The signature covers ``canonical_bytes(payload)``:

1. Take the response object and drop the two members ``signature`` and ``key_id`` (every other member,
   including any future ones, is signed).
2. Serialise as RFC 8785 (JSON Canonicalization Scheme) UTF-8 bytes: members sorted by key, no
   insignificant whitespace, strings in UTF-8 (NOT ``\\uXXXX``-escaped for non-ASCII), integers in plain
   decimal. Floats are not permitted anywhere in the signed object.
3. If the ``rfc8785`` package is importable it is used. Otherwise the fallback is exactly::

       json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                  allow_nan=False).encode("utf-8")

   which is byte-identical to RFC 8785 for objects made of strings, integers, booleans, null, arrays and
   objects with BMP keys (everything the snapshot contains). Server and client must therefore both use
   integer-only numbers and ``ensure_ascii=False``.
4. Sign those bytes with Ed25519 (RFC 8032, pure, no pre-hash). Public keys are configured on the client
   as base64 of the raw 32-byte key (a PEM ``SubjectPublicKeyInfo`` is also accepted).

Client-side validity rules (all failures fail closed -> :class:`~ales_sdk.errors.SnapshotError`)
------------------------------------------------------------------------------------------------
* signature verifies under the configured key (``key_id`` selects among several configured keys);
* ``tenant_id`` equals the client's tenant;
* all fields have the right types; ``lease_seconds`` > 0; ``issued_at`` parses and carries a timezone;
* anti-replay: the lease is *not* simply restarted at receipt. The wall-clock age of the snapshot
  (``now - issued_at``) beyond ``max_clock_skew`` is deducted from the lease, and a snapshot whose lease
  is already spent on arrival is rejected as expired. The remaining lease is then enforced against the
  client's monotonic clock from the moment of receipt (immune to wall-clock changes afterwards);
* anti-rollback is enforced by the client (epoch must not decrease between accepted snapshots).
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .errors import ConfigError, SnapshotError

UNSIGNED_FIELDS = ("signature", "key_id")
DEFAULT_MAX_CLOCK_SKEW = 30.0


def _reject_floats(obj: Any) -> None:
    if isinstance(obj, float):
        raise SnapshotError("bad_format", "floats are not permitted in a signed snapshot")
    if isinstance(obj, Mapping):
        for v in obj.values():
            _reject_floats(v)
    elif isinstance(obj, list | tuple):
        for v in obj:
            _reject_floats(v)


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """The exact bytes that are signed. See the module docstring for the byte-level contract."""
    obj = {k: v for k, v in payload.items() if k not in UNSIGNED_FIELDS}
    _reject_floats(obj)
    try:
        import rfc8785  # type: ignore[import-not-found]
    except ImportError:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    result = rfc8785.dumps(obj)
    return result if isinstance(result, bytes) else str(result).encode("utf-8")


def _b64decode(s: str) -> bytes:
    t = s.strip()
    pad = "=" * (-len(t) % 4)
    try:
        if "-" in t or "_" in t:
            return base64.urlsafe_b64decode(t + pad)
        return base64.b64decode(t + pad, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError("invalid base64") from e


def load_public_key(key: str | bytes) -> Any:
    """Parse an Ed25519 public key (base64 raw 32 bytes, raw 32 bytes, or PEM). Raises ConfigError."""
    try:
        from cryptography.exceptions import UnsupportedAlgorithm  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError as e:  # pragma: no cover - environment dependent
        raise ConfigError(
            "snapshot verification requires the 'cryptography' package (pip install cryptography)"
        ) from e
    try:
        if isinstance(key, bytes) and len(key) == 32:
            return Ed25519PublicKey.from_public_bytes(key)
        text = key.decode("ascii") if isinstance(key, bytes) else key
        if "BEGIN PUBLIC KEY" in text:
            pk = load_pem_public_key(text.encode("ascii"))
            if not isinstance(pk, Ed25519PublicKey):
                raise ConfigError("snapshot_public_key PEM is not an Ed25519 key")
            return pk
        raw = _b64decode(text)
        if len(raw) != 32:
            raise ConfigError(f"snapshot_public_key must decode to 32 bytes, got {len(raw)}")
        return Ed25519PublicKey.from_public_bytes(raw)
    except ConfigError:
        raise
    except (ValueError, TypeError, UnicodeError) as e:
        raise ConfigError(f"invalid snapshot_public_key: {e}") from e


def load_public_keys(spec: str | bytes | Mapping[str, str | bytes]) -> dict[str | None, Any]:
    """Normalise the ``snapshot_public_key`` constructor argument.

    A single key is stored under ``None`` (matches any/absent ``key_id``). A mapping ``{key_id: key}``
    supports rotation: the snapshot's ``key_id`` must then be present in the mapping.
    """
    if isinstance(spec, Mapping):
        if not spec:
            raise ConfigError("snapshot_public_key mapping is empty")
        return {str(k): load_public_key(v) for k, v in spec.items()}
    return {None: load_public_key(spec)}


@dataclass(frozen=True)
class Snapshot:
    """A verified snapshot plus the client-side timing needed to judge its lease."""

    tenant_id: str
    revocation_epoch: int
    policy_version: str
    issued_at: datetime
    lease_seconds: int
    key_id: str | None
    received_at: float  # client monotonic clock at receipt
    effective_lease: float  # lease actually granted after replay-age deduction

    def deadline(self, max_lease: float | None = None) -> float:
        lease = self.effective_lease if max_lease is None else min(self.effective_lease, max_lease)
        return self.received_at + lease

    def valid_at(self, now: float, max_lease: float | None = None) -> bool:
        """True while the monotonic clock ``now`` is strictly before the lease deadline."""
        return now < self.deadline(max_lease)


def verify_snapshot(
    data: Any,
    *,
    keys: Mapping[str | None, Any],
    tenant_id: str,
    received_at: float,
    wall_now: float,
    max_clock_skew: float = DEFAULT_MAX_CLOCK_SKEW,
) -> Snapshot:
    """Verify a ``/v1/snapshot`` response. Raises :class:`SnapshotError` on any problem."""
    from cryptography.exceptions import InvalidSignature

    if not isinstance(data, Mapping):
        raise SnapshotError("bad_format", "snapshot is not a JSON object")
    sig_s = data.get("signature")
    if not isinstance(sig_s, str) or not sig_s:
        raise SnapshotError("missing_signature")
    key_id = data.get("key_id")
    if key_id is not None and not isinstance(key_id, str):
        raise SnapshotError("bad_format", "key_id must be a string")
    if None in keys:
        key = keys[None]
    elif key_id is not None and key_id in keys:
        key = keys[key_id]
    else:
        raise SnapshotError("unknown_key_id", f"key_id {key_id!r} is not a configured snapshot key")
    try:
        signature = _b64decode(sig_s)
        key.verify(signature, canonical_bytes(data))
    except (InvalidSignature, ValueError) as e:
        raise SnapshotError("bad_signature", "signature does not verify") from e

    # Fields are only trusted after the signature has verified.
    tid = data.get("tenant_id")
    epoch = data.get("revocation_epoch")
    pv = data.get("policy_version")
    issued = data.get("issued_at")
    lease = data.get("lease_seconds")
    if not isinstance(tid, str) or not isinstance(pv, str) or not isinstance(issued, str):
        raise SnapshotError("bad_format", "tenant_id/policy_version/issued_at must be strings")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise SnapshotError("bad_format", "revocation_epoch must be a non-negative integer")
    if isinstance(lease, bool) or not isinstance(lease, int) or lease <= 0:
        raise SnapshotError("bad_format", "lease_seconds must be a positive integer")
    if tid != tenant_id:
        raise SnapshotError("tenant_mismatch", f"snapshot is for tenant {tid!r}, client is {tenant_id!r}")
    try:
        issued_dt = datetime.fromisoformat(issued)
    except ValueError as e:
        raise SnapshotError("bad_format", f"issued_at is not an RFC 3339 timestamp: {issued!r}") from e
    if issued_dt.tzinfo is None:
        raise SnapshotError("bad_format", "issued_at must carry a timezone")
    issued_dt = issued_dt.astimezone(UTC)

    age = wall_now - issued_dt.timestamp()
    effective = float(lease) - max(0.0, age - max_clock_skew)
    if effective <= 0:
        raise SnapshotError("expired", f"snapshot lease already spent on arrival (age {age:.0f}s)")
    return Snapshot(
        tenant_id=tid,
        revocation_epoch=epoch,
        policy_version=pv,
        issued_at=issued_dt,
        lease_seconds=lease,
        key_id=key_id,
        received_at=received_at,
        effective_lease=effective,
    )
