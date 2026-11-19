"""Webhook (push) connector for systems that notify us of changes.

Wire format (JSON body)::

    {"action": "deleted"|"updated"|"acl_changed", "object_id": "...", "version": "...",
     "digest": "<sha256 hex, optional>", "acl": {...optional...}, "timestamp": <epoch seconds | ISO-8601>}

Authentication: HMAC-SHA256 over the RAW request body, hex, in ``signature_header``
(``sha256=<hex>`` or bare hex). Pass ``raw_body`` exactly as received; if omitted, the canonical JSON of
``payload`` (``sort_keys``, compact separators) is signed -- senders must then sign that form. Comparison is
constant-time. ``timestamp`` is REQUIRED and must be within ``max_skew_seconds`` of now (both directions);
an identical accepted body is also rejected inside the window (exact replay). The timestamp is covered by
the signature because it is inside the body.

Semantics reuse the shared diff engine, so they equal the filesystem connector: ``updated`` with a new
``version`` -> version_superseded + re-register; ``acl_changed`` narrowing -> acl_changed; ``deleted`` ->
deleted; unknown ``deleted`` is a no-op. This is a push connector: ``scan`` registers nothing on its own,
``watch_once`` drains the events produced by ``handle`` since the last call. Because pushes can be lost,
operators should also schedule a reconcile (full export -> ``apply_object_change``) -- health says so.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ales_sdk.client import InvariantClient

from .spi import (
    CheckpointStore,
    ConnectorHealth,
    Envelope,
    RemoteObject,
    RevocationEvent,
    TrackedConnector,
)


class WebhookError(Exception):
    """Base class; ``status`` is the suggested HTTP status."""

    status = 400


class WebhookAuthError(WebhookError):
    status = 401


class WebhookReplayError(WebhookError):
    status = 409


class WebhookPayloadError(WebhookError):
    status = 422


@dataclass
class HandleResult:
    action: str
    object_id: str
    envelope: Envelope | None = None
    events: list[RevocationEvent] = field(default_factory=list)


def sign_body(raw_body: bytes, secret: str | bytes) -> str:
    key = secret.encode() if isinstance(secret, str) else secret
    return "sha256=" + hmac.new(key, raw_body, hashlib.sha256).hexdigest()


def canonical_body(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _parse_ts(v: Any) -> float:
    if isinstance(v, bool):
        raise TypeError("bad timestamp")
    if isinstance(v, int | float):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return datetime.fromisoformat(v).timestamp()
    raise TypeError("bad timestamp")


class WebhookConnector(TrackedConnector):
    mode = "events"
    source_system = "webhook"
    actor = "ales-webhook-connector"

    def __init__(
        self,
        client: InvariantClient,
        tenant_id: str,
        *,
        shared_secret: str | bytes | None = None,
        connector_id: str = "webhook",
        source_system: str = "webhook",
        checkpoint: CheckpointStore | None = None,
        max_skew_seconds: float = 300.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(client, tenant_id, connector_id, checkpoint, clock=clock)
        self._secret = shared_secret
        self.source_system = source_system
        self.max_skew_seconds = max_skew_seconds
        self._pending_events: list[RevocationEvent] = []
        self._seen: dict[str, float] = {}  # body-hmac -> accepted-at, pruned to the replay window
        self.rejected = 0

    def __repr__(self) -> str:
        return f"WebhookConnector(connector_id={self.connector_id!r})"

    def _verify(self, raw: bytes, signature_header: str | None, secret: str | bytes | None) -> str:
        secret = secret if secret is not None else self._secret
        if not secret:
            raise WebhookAuthError("no shared secret configured")
        if not signature_header:
            raise WebhookAuthError("missing signature")
        signature = signature_header.strip()
        if signature.lower().startswith("sha256="):
            signature = signature[7:]
        expected = sign_body(raw, secret)[7:]
        if not hmac.compare_digest(signature.lower().encode(), expected.encode()):
            raise WebhookAuthError("invalid signature")
        return expected

    def _check_fresh(self, payload: dict[str, Any], mac: str) -> None:
        if "timestamp" not in payload:
            raise WebhookReplayError("timestamp required")
        try:
            ts = _parse_ts(payload["timestamp"])
        except (ValueError, TypeError) as exc:
            raise WebhookPayloadError("unparseable timestamp") from exc
        now = self._clock()
        if abs(now - ts) > self.max_skew_seconds:
            raise WebhookReplayError("timestamp outside replay window")
        self._seen = {k: t for k, t in self._seen.items() if now - t <= self.max_skew_seconds}
        if mac in self._seen:
            raise WebhookReplayError("duplicate delivery inside replay window")

    def handle(
        self,
        payload: dict[str, Any],
        *,
        signature_header: str | None,
        shared_secret: str | bytes | None = None,
        raw_body: bytes | None = None,
    ) -> HandleResult:
        try:
            raw = raw_body if raw_body is not None else canonical_body(payload)
            mac = self._verify(raw, signature_header, shared_secret)
            self._check_fresh(payload, mac)
            result = self._apply(payload)
        except WebhookError as exc:
            self.rejected += 1
            self._record_error(f"{type(exc).__name__}: {exc}")
            raise
        self._seen[mac] = self._clock()
        self._pending_events.extend(result.events)
        self._mark_synced()
        return result

    def _apply(self, p: dict[str, Any]) -> HandleResult:
        action = p.get("action")
        oid = p.get("object_id")
        if action not in ("deleted", "updated", "acl_changed") or not isinstance(oid, str) or not oid:
            raise WebhookPayloadError("action must be deleted|updated|acl_changed and object_id a string")
        if action == "deleted":
            deleted = self.apply_object_change(oid, None)
            return HandleResult(action, oid, None, deleted)

        version = p.get("version")
        if not isinstance(version, str | int) or not str(version):
            raise WebhookPayloadError("version required for updated/acl_changed")
        known = self.state.get(oid)
        raw_acl = p.get("acl")
        if action == "acl_changed" and not isinstance(raw_acl, dict):
            raise WebhookPayloadError("acl required for acl_changed")
        if action == "acl_changed" and known is None:
            raise WebhookPayloadError("acl_changed for an unknown object; send 'updated' first")
        try:
            acl = raw_acl if isinstance(raw_acl, dict) else (known["acl"] if known else None)
            if action == "acl_changed" and known and "digest" not in p and str(version) == known["hint"]:
                digest = known["digest"].removeprefix("sha256:")
            else:
                digest = str(p.get("digest") or hashlib.sha256(f"{oid}\0{version}".encode()).hexdigest())
            digest = digest.removeprefix("sha256:")
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("digest must be sha256 hex")
            obj = RemoteObject(
                id=oid,
                version_hint=str(version),
                digest=digest,
                acl=acl,
                metadata={"digest_mode": "sha256" if p.get("digest") else "etag"},
            )
            events, env = self._upsert(obj)
        except ValueError as exc:
            raise WebhookPayloadError(str(exc)) from exc
        finally:
            self._save()
        return HandleResult(action, oid, env, events)

    def scan(self) -> list[Envelope]:
        return []  # push-only: sources are registered when their first 'updated' arrives

    def watch_once(self) -> list[RevocationEvent]:
        events, self._pending_events = self._pending_events, []
        return events

    def health(self) -> ConnectorHealth:
        h = super().health()
        h.freshness_sla_seconds = None
        h.details.update(
            rejected=self.rejected,
            note="Push connector: latency is delivery latency; lost webhooks are undetectable without a "
            "periodic reconcile against the source system.",
        )
        return h
