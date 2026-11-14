"""Helpers to build spec-valid context envelopes."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

CLASSIFICATION_ORDER = ["public", "internal", "confidential", "restricted"]
TRUST_ORDER = ["verified", "untrusted", "quarantined"]
DERIVATIVE_KINDS = {"chunk", "embedding", "summary", "memory", "cache", "artifact"}


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def digest(content: bytes | str) -> str:
    if isinstance(content, str):
        content = content.encode("utf-8")
    return "sha256:" + hashlib.sha256(content).hexdigest()


def new_source(
    tenant_id: str,
    object_id: str,
    content: bytes | str,
    source_system: str,
    *,
    object_version: str = "1",
    classification: str = "internal",
    trust_state: str = "verified",
    principal_scope: Iterable[str] | None = None,
    purpose_scope: Iterable[str] | None = None,
    source_acl_ref: str | None = None,
    policy_version: str = "v1",
    valid_from: str | None = None,
    expires_at: str | None = None,
    context_id: str | None = None,
    successor_of: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    env: dict[str, Any] = {
        "context_id": context_id or str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "object_id": object_id,
        "object_version": object_version,
        "content_digest": digest(content),
        "kind": "source",
        "source_system": source_system,
        "source_acl_ref": source_acl_ref,
        "classification": classification,
        "trust_state": trust_state,
        "parent_refs": [],
        "policy_version": policy_version,
        "valid_from": valid_from or now_iso(),
        "expires_at": expires_at,
    }
    if principal_scope is not None:
        env["principal_scope"] = list(principal_scope)
    if purpose_scope is not None:
        env["purpose_scope"] = list(purpose_scope)
    if successor_of is not None:
        env["successor_of"] = {
            "context_id": successor_of["context_id"],
            "object_version": successor_of["object_version"],
        }
    return env


def _parent_ref(p: Mapping[str, Any]) -> dict[str, str]:
    return {"context_id": p["context_id"], "object_version": p["object_version"]}


def new_derivative(
    kind: str,
    parents: Iterable[Mapping[str, Any]],
    tenant_id: str,
    object_id: str,
    content: bytes | str,
    *,
    source_system: str = "ales-sdk",
    object_version: str = "1",
    policy_version: str = "v1",
    classification: str | None = None,
    trust_state: str | None = None,
    valid_from: str | None = None,
    context_id: str | None = None,
) -> dict[str, Any]:
    """Build a derivative envelope.

    ``parents`` are envelopes (or dicts with at least context_id + object_version). When parents are
    full envelopes, classification/trust/scopes/expiry are propagated conservatively per spec (the
    server remains authoritative). Without parent metadata it defaults to the most restrictive values.
    """
    if kind not in DERIVATIVE_KINDS:
        raise ValueError(f"derivative kind must be one of {sorted(DERIVATIVE_KINDS)}, got {kind!r}")
    plist = list(parents)
    if not plist:
        raise ValueError("derivatives require at least one parent")

    cls = [p["classification"] for p in plist if "classification" in p]
    trust = [p["trust_state"] for p in plist if "trust_state" in p]
    env: dict[str, Any] = {
        "context_id": context_id or str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "object_id": object_id,
        "object_version": object_version,
        "content_digest": digest(content),
        "kind": kind,
        "source_system": source_system,
        "classification": classification
        or (max(cls, key=CLASSIFICATION_ORDER.index) if cls else "restricted"),
        "trust_state": trust_state or (max(trust, key=TRUST_ORDER.index) if trust else "untrusted"),
        "parent_refs": [_parent_ref(p) for p in plist],
        "policy_version": policy_version,
        "valid_from": valid_from or now_iso(),
    }
    for field in ("principal_scope", "purpose_scope"):
        scopes = [set(p[field]) for p in plist if p.get(field) is not None]
        if scopes:
            env[field] = sorted(set.intersection(*scopes))
    expiries = [p["expires_at"] for p in plist if p.get("expires_at")]
    if expiries:
        env["expires_at"] = min(expiries)
    return env
