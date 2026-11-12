"""Physical purge: remove revoked objects from the stores that hold them.

Safety never depends on this module. Use-time decisions are tombstone-based, so a purge that is late,
failing or dead-lettered can delay cleanup but cannot re-expose data. Purge exists so the bytes are
actually gone (storage, breach surface, "right to erasure" evidence).

A ``PurgeRegistry`` maps an outbox ``store_kind`` (chunk / embedding / summary / memory / cache /
artifact, or ``"*"`` for every kind) to one or more ``PurgeTarget``s. ``as_outbox_handlers()`` yields the
handler dict an ``OutboxDispatcher`` (or ``create_app(outbox_handlers=...)``) consumes. The registry is
also a read-only ``Mapping[str, handler]``, so it can be passed to ``create_app`` directly.

Contract for targets: ``purge(row)`` must be idempotent (outbox delivery is at-least-once), must treat
"never stored here" as success, and must raise on a real failure so the dispatcher retries. When a row's
kind has several targets every target is attempted even if an earlier one fails; the failures are then
raised together, so a re-run only has to redo what is left (hence the idempotency requirement).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from typing import Any, Protocol

WILDCARD = "*"


class PurgeRow(Protocol):
    """The slice of an outbox row a target needs (``ales_core.InvalidationOutbox`` satisfies it)."""

    tenant_id: str
    context_id: str
    version: str
    store_kind: str


class PurgeTarget(Protocol):
    name: str

    def purge(self, row: PurgeRow) -> None: ...


class PurgeError(Exception):
    """One or more targets failed for a row; ``failures`` is ``[(target name, exception)]``."""

    def __init__(self, row_desc: str, failures: list[tuple[str, Exception]]) -> None:
        self.failures = failures
        detail = "; ".join(f"{n}: {type(e).__name__}: {e}" for n, e in failures)
        super().__init__(f"purge failed for {row_desc}: {detail}")


class VectorPurgeTarget:
    """Deletes the vector row stored under the object's ``context_id`` (see ``GuardedVectorStore``).

    The row's version is passed to the backend so that a purge for a superseded version does not delete
    a newer version that was re-stored under the same ``context_id``.
    """

    def __init__(self, backend: Any, name: str = "vector") -> None:
        self.backend = backend
        self.name = name

    def purge(self, row: PurgeRow) -> None:
        self.backend.delete(row.context_id, version=row.version)


def cache_index_key(prefix: str, context_id: str) -> str:
    return f"{prefix}__ales_idx__{context_id}"


class CachePurgeTarget:
    """Deletes a ``GuardedCache`` entry through the reverse index written by ``GuardedCache.put``.

    The data key is deleted before the index key, so a crash in between leaves the index in place and a
    re-run finishes the job. An object with no index record (never cached, already purged, or written
    before the index existed) is a success.
    """

    def __init__(self, redis_like: Any, prefix: str = "", name: str = "cache") -> None:
        self.redis = redis_like
        self.prefix = prefix
        self.name = name

    def purge(self, row: PurgeRow) -> None:
        idx_key = cache_index_key(self.prefix, row.context_id)
        raw = self.redis.get(idx_key)
        if raw is None:
            return
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        try:
            rec = json.loads(raw)
            key, version = str(rec["key"]), rec.get("version")
        except (ValueError, KeyError, TypeError):
            # Unreadable index: nothing safe to delete by key. Drop the index so it cannot wedge retries.
            self.redis.delete(idx_key)
            return
        if version is not None and version != row.version:
            return  # the key now holds a newer version of this object; that version has its own outbox row
        self.redis.delete(self.prefix + key)
        self.redis.delete(idx_key)


class PurgeRegistry(Mapping[str, Callable[[Any], None]]):
    def __init__(self) -> None:
        self._targets: dict[str, list[PurgeTarget]] = {}

    def register(self, store_kind: str, target: PurgeTarget) -> PurgeRegistry:
        self._targets.setdefault(store_kind, []).append(target)
        return self

    def register_many(self, store_kinds: tuple[str, ...] | list[str], target: PurgeTarget) -> PurgeRegistry:
        for k in store_kinds:
            self.register(k, target)
        return self

    def targets_for(self, store_kind: str) -> list[PurgeTarget]:
        specific = self._targets.get(store_kind, []) if store_kind != WILDCARD else []
        return [*specific, *self._targets.get(WILDCARD, [])]

    def purge(self, row: PurgeRow) -> None:
        """Purge ``row`` from every target registered for its kind; raise :class:`PurgeError` on failure."""
        failures: list[tuple[str, Exception]] = []
        for t in self.targets_for(row.store_kind):
            try:
                t.purge(row)
            except Exception as exc:  # noqa: BLE001 - attempt the remaining targets, then fail the row
                failures.append((t.name, exc))
        if failures:
            raise PurgeError(f"{row.store_kind}:{row.context_id}@{row.version}", failures)

    def _handler(self, kind: str) -> Callable[[Any], None]:
        def handler(row: Any) -> None:
            self.purge(row)

        handler.purge_targets = [t.name for t in self.targets_for(kind)]  # type: ignore[attr-defined]
        handler.__name__ = f"purge_{kind.replace('*', 'any')}"
        return handler

    def as_outbox_handlers(self) -> dict[str, Callable[[Any], None]]:
        return {kind: self._handler(kind) for kind in self._targets}

    # -- Mapping view (lets create_app(outbox_handlers=registry) work unchanged) ------------------
    def __getitem__(self, kind: str) -> Callable[[Any], None]:
        if kind not in self._targets:
            raise KeyError(kind)
        return self._handler(kind)

    def __iter__(self) -> Iterator[str]:
        return iter(self._targets)

    def __len__(self) -> int:
        return len(self._targets)
