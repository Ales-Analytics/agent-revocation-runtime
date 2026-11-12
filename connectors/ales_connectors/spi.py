"""Connector SPI: the contract every ALES source connector implements, plus the shared diff engine.

Semantics mirror ``ales_adapters.fs_source`` exactly:

* object removed                      -> ``deleted``
* content/version changed             -> ``version_superseded`` (old context revoked, new version
                                         registered under a NEW context_id)
* ACL narrowed (higher classification, or a principal/purpose scope member removed, or a previously
  unrestricted scope becomes restricted) -> ``acl_changed`` (old context revoked, re-registered)
* ACL widened                         -> silent re-register (nothing to revoke)

Freshness honesty: a polling connector can only notice a change at its next poll, so the worst-case
revocation latency is ``poll_interval_seconds`` plus the sync duration. ``health()`` reports this as
``freshness_sla_seconds`` and ``lag_seconds`` (time since the last successful sync). Event-driven
connectors (webhook / S3 notifications) shorten the window but still need a periodic reconcile poll
to catch lost events; that is why ``mode`` is advisory, never a guarantee.

Fail-safe rule: if listing the remote fails (or is truncated), ``watch_once`` raises BEFORE diffing, so
an outage can never be mistaken for "everything was deleted" or "nothing changed" silently.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Literal, Protocol, runtime_checkable

from ales_sdk.client import InvariantClient
from ales_sdk.envelope import CLASSIFICATION_ORDER, new_source

Envelope = dict[str, Any]
RevocationEvent = dict[str, Any]

ACL_SUFFIX = ".acl.json"
DEFAULT_ACL: dict[str, Any] = {"classification": "internal", "principal_scope": None, "purpose_scope": None}
FAIL_CLOSED_ACL: dict[str, Any] = {"classification": "restricted", "principal_scope": [], "purpose_scope": []}
EVENT_TYPES = ("deleted", "version_superseded", "acl_changed")


# -- ACL helpers -----------------------------------------------------------------------------------
def acl_digest(acl: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(acl, sort_keys=True).encode()).hexdigest()[:16]


def _scope_loses(old: list[str] | None, new: list[str] | None) -> bool:
    """True if ``new`` grants access to fewer parties than ``old`` (None = unrestricted)."""
    if old is None:
        return new is not None
    if new is None:
        return False
    return bool(set(old) - set(new))


def acl_narrowed(old: dict[str, Any], new: dict[str, Any]) -> bool:
    if CLASSIFICATION_ORDER.index(new["classification"]) > CLASSIFICATION_ORDER.index(old["classification"]):
        return True
    return _scope_loses(old["principal_scope"], new["principal_scope"]) or _scope_loses(
        old["purpose_scope"], new["purpose_scope"]
    )


def normalize_acl(raw: dict[str, Any] | None, default: dict[str, Any] | None = None) -> dict[str, Any]:
    """Overlay a (possibly partial) ACL dict on the defaults. Raises ValueError on a bad classification."""
    acl = dict(default or DEFAULT_ACL)
    for k in acl:
        if raw and raw.get(k) is not None:
            acl[k] = raw[k]
    if acl["classification"] not in CLASSIFICATION_ORDER:
        raise ValueError(f"unknown classification {acl['classification']!r}")
    for k in ("principal_scope", "purpose_scope"):
        if acl[k] is not None:
            if not isinstance(acl[k], list):
                raise ValueError(f"{k} must be a list or null")
            acl[k] = sorted(str(x) for x in acl[k])
    return acl


def parse_acl_sidecar(data: bytes | str | None, default: dict[str, Any] | None = None) -> dict[str, Any]:
    """Parse a ``<key>.acl.json`` body. Missing -> default. Malformed -> FAIL CLOSED (restricted, nobody).

    Failing closed means a corrupted sidecar can only narrow access (and trigger a revocation), never
    silently leave a sensitive object looking ``internal``/unrestricted.
    """
    if data is None:
        return dict(default or DEFAULT_ACL)
    try:
        raw = json.loads(data)
        if not isinstance(raw, dict):
            raise TypeError("acl sidecar must be a JSON object")
        return normalize_acl(raw, default)
    except (ValueError, TypeError):
        return dict(FAIL_CLOSED_ACL)


def sidecar_key(key: str) -> str:
    return key + ACL_SUFFIX


# -- data types --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class RemoteObject:
    """One object as seen in a remote listing.

    ``version_hint`` is an opaque change-detection token (ETag, ETag+VersionId, ...). ``digest`` is the
    64-hex sha256 backing the envelope's ``content_digest``; if None the connector's ``resolve_digest``
    is called lazily, and only for objects whose hint changed. ``metadata['digest_mode']`` records how the
    digest was obtained: ``sha256`` (real content hash) or ``etag`` (hash of the opaque ETag identity).
    """

    id: str
    version_hint: str
    digest: str | None = None
    acl: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ConnectorHealth:
    connector_id: str
    last_sync: float | None  # epoch seconds of the last successful sync, None if never
    lag_seconds: float | None  # now - last_sync (staleness); None if never synced
    mode: Literal["events", "polling"]
    coverage: dict[str, bool]  # event_type -> can this connector detect it?
    errors: list[str] = field(default_factory=list)
    freshness_sla_seconds: float | None = None  # worst-case detection latency (polling: poll interval)
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "connector_id": self.connector_id,
            "last_sync": self.last_sync,
            "lag_seconds": self.lag_seconds,
            "mode": self.mode,
            "coverage": dict(self.coverage),
            "errors": list(self.errors),
            "freshness_sla_seconds": self.freshness_sla_seconds,
            "details": dict(self.details),
        }


# -- protocols ---------------------------------------------------------------------------------------
@runtime_checkable
class SourceConnector(Protocol):
    connector_id: str

    def scan(self) -> list[Envelope]:
        """Register sources not yet seen. Returns the envelopes registered."""
        ...

    def watch_once(self) -> list[RevocationEvent]:
        """Detect delete / supersede / ACL-narrow, register new versions. Returns emitted events."""
        ...

    def health(self) -> ConnectorHealth: ...


@runtime_checkable
class CheckpointStore(Protocol):
    def get(self, key: str, default: Any = None) -> Any: ...

    def put(self, key: str, value: Any) -> None: ...


class InMemoryCheckpoint:
    def __init__(self) -> None:
        self._d: dict[str, Any] = {}

    def get(self, key: str, default: Any = None) -> Any:
        v = self._d.get(key)
        return default if v is None else json.loads(json.dumps(v))

    def put(self, key: str, value: Any) -> None:
        self._d[key] = json.loads(json.dumps(value))  # round-trip: enforce JSON-ability, no aliasing


class FileCheckpoint:
    """JSON file holding ``{key: value}``; one file may be shared by many connectors. Atomic writes."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            v = self._load().get(key)
        return default if v is None else v

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            data = self._load()
            data[key] = value
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=self.path.name, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2, sort_keys=True)
                os.replace(tmp, self.path)
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise


# -- shared tracking engine ----------------------------------------------------------------------------
def version_from_digest(digest_hex: str) -> str:
    return digest_hex[:12]


class TrackedConnector(ABC):
    """State + registration + per-object diff. Subclassed by polling and push connectors."""

    mode: Literal["events", "polling"] = "polling"
    source_system: str = "unknown"
    actor: str = "ales-connector"
    coverage: ClassVar[dict[str, bool]] = {"deleted": True, "version_superseded": True, "acl_changed": True}

    def __init__(
        self,
        client: InvariantClient,
        tenant_id: str,
        connector_id: str,
        checkpoint: CheckpointStore | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.client = client
        self.tenant_id = tenant_id
        self.connector_id = connector_id
        self.checkpoint: CheckpointStore = checkpoint if checkpoint is not None else InMemoryCheckpoint()
        self._clock = clock
        self._ck_key = f"{connector_id}:state"
        self.state: dict[str, dict[str, Any]] = self.checkpoint.get(self._ck_key, {}) or {}
        self.last_sync: float | None = self.checkpoint.get(f"{connector_id}:last_sync")
        self.errors: list[str] = []

    # -- persistence
    def _save(self) -> None:
        self.checkpoint.put(self._ck_key, self.state)

    def _mark_synced(self) -> None:
        self.last_sync = self._clock()
        self.checkpoint.put(f"{self.connector_id}:last_sync", self.last_sync)

    def _record_error(self, msg: str) -> None:
        self.errors = (self.errors + [msg])[-20:]

    # -- primitives
    def _register(self, obj: RemoteObject, digest_hex: str, mode: str, acl: dict[str, Any]) -> Envelope:
        version = version_from_digest(digest_hex)
        env = new_source(
            self.tenant_id,
            obj.id,
            b"",
            self.source_system,
            object_version=version,
            classification=acl["classification"],
            principal_scope=acl["principal_scope"],
            purpose_scope=acl["purpose_scope"],
        )
        env["content_digest"] = "sha256:" + digest_hex
        self.client.register_source(env)
        self.state[obj.id] = {
            "context_id": env["context_id"],
            "version": version,
            "hint": obj.version_hint,
            "digest": env["content_digest"],
            "digest_mode": mode,
            "acl": acl,
            "acl_digest": acl_digest(acl),
        }
        return env

    def _revoke(self, entry: dict[str, Any], reason: str) -> RevocationEvent:
        event = {
            "tenant_id": self.tenant_id,
            "source_id": entry["context_id"],
            "source_version": entry["version"],
            "reason": reason,
            "actor": self.actor,
        }
        resp = self.client.submit_revocation(event)
        return {**event, "event_id": resp.get("event_id"), "revocation_epoch": resp.get("revocation_epoch")}

    def resolve_digest(self, obj: RemoteObject) -> tuple[str, str]:
        """Return ``(sha256_hex, digest_mode)`` for an object. Default: use ``obj.digest`` or hash the hint."""
        if obj.digest:
            return obj.digest.removeprefix("sha256:"), str(obj.metadata.get("digest_mode", "sha256"))
        return hashlib.sha256(f"hint:{obj.version_hint}".encode()).hexdigest(), "etag"

    def _delete(self, object_id: str) -> list[RevocationEvent]:
        entry = self.state.get(object_id)
        if entry is None:
            return []
        ev = self._revoke(entry, "deleted")
        self.state.pop(object_id, None)
        return [ev]

    def _upsert(self, obj: RemoteObject) -> tuple[list[RevocationEvent], Envelope | None]:
        """Core per-object diff. Returns (events, envelope registered or None)."""
        acl = normalize_acl(obj.acl)
        entry = self.state.get(obj.id)
        if entry is None:
            digest_hex, mode = self.resolve_digest(obj)
            return [], self._register(obj, digest_hex, mode, acl)

        if obj.version_hint == entry.get("hint"):
            digest_hex, mode = entry["digest"].removeprefix("sha256:"), entry["digest_mode"]
        else:
            digest_hex, mode = self.resolve_digest(obj)
        version = version_from_digest(digest_hex)

        if version != entry["version"]:
            ev = self._revoke(entry, "version_superseded")
            return [ev], self._register(obj, digest_hex, mode, acl)
        if acl_digest(acl) != entry["acl_digest"]:
            events = [self._revoke(entry, "acl_changed")] if acl_narrowed(entry["acl"], acl) else []
            return events, self._register(obj, digest_hex, mode, acl)
        if obj.version_hint != entry.get("hint"):  # same content, new hint (e.g. re-put): just track it
            entry["hint"] = obj.version_hint
        return [], None

    def apply_object_change(self, object_id: str, obj: RemoteObject | None) -> list[RevocationEvent]:
        """Apply one observed change (``obj`` None = gone). Used by event-driven paths. Persists state."""
        try:
            events = self._delete(object_id) if obj is None else self._upsert(obj)[0]
        finally:
            self._save()
        return events

    # -- SPI
    @abstractmethod
    def scan(self) -> list[Envelope]: ...

    @abstractmethod
    def watch_once(self) -> list[RevocationEvent]: ...

    def health(self) -> ConnectorHealth:
        now = self._clock()
        return ConnectorHealth(
            connector_id=self.connector_id,
            last_sync=self.last_sync,
            lag_seconds=None if self.last_sync is None else max(0.0, now - self.last_sync),
            mode=self.mode,
            coverage=dict(self.coverage),
            errors=list(self.errors),
            details={"tracked_objects": len(self.state)},
        )


class PollingConnector(TrackedConnector):
    """Diff a full remote listing against the checkpoint. Subclasses implement ``list_objects``."""

    def __init__(
        self,
        client: InvariantClient,
        tenant_id: str,
        connector_id: str,
        checkpoint: CheckpointStore | None = None,
        *,
        poll_interval_seconds: float = 60.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(client, tenant_id, connector_id, checkpoint, clock=clock)
        self.poll_interval_seconds = poll_interval_seconds

    @abstractmethod
    def list_objects(self) -> list[RemoteObject]:
        """Return the COMPLETE current object set (never a partial page); raise on any failure."""

    def _list(self) -> list[RemoteObject]:
        try:
            objs = self.list_objects()
        except Exception as exc:
            self._record_error(f"list_objects failed: {type(exc).__name__}: {exc}")
            raise
        seen: dict[str, RemoteObject] = {}
        for o in objs:
            seen[o.id] = o
        return list(seen.values())

    def scan(self) -> list[Envelope]:
        registered: list[Envelope] = []
        objs = self._list()
        try:
            for obj in sorted(objs, key=lambda o: o.id):
                if obj.id in self.state:
                    continue
                digest_hex, mode = self.resolve_digest(obj)
                registered.append(self._register(obj, digest_hex, mode, normalize_acl(obj.acl)))
        finally:
            self._save()
        self._mark_synced()
        return registered

    def watch_once(self) -> list[RevocationEvent]:
        objs = {o.id: o for o in self._list()}
        events: list[RevocationEvent] = []
        try:
            for oid in sorted(set(self.state) - set(objs)):
                events.extend(self._delete(oid))
            for oid in sorted(objs):
                evs, _env = self._upsert(objs[oid])  # new objects are registered here too
                events.extend(evs)
        finally:
            self._save()
        self._mark_synced()
        return events

    def health(self) -> ConnectorHealth:
        h = super().health()
        h.freshness_sla_seconds = self.poll_interval_seconds
        h.details["note"] = (
            "Polling: a change is detected at the next poll; worst-case latency is poll_interval_seconds "
            "plus sync duration. Not real-time."
        )
        return h
