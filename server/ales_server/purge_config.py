"""Environment-driven purge wiring (``ALES_PURGE_TARGETS``) with post-purge verification.

``ALES_PURGE_TARGETS`` is a JSON list of target specs::

    [
      {"kind": "cache", "type": "redis",   "url": "redis://host:6379/0", "prefix": ""},
      {"kind": "chunk", "type": "qdrant",  "url": "http://qdrant:6333", "collection": "ales_vectors"},
      {"kind": ["chunk", "embedding"], "type": "pgvector",
       "url": "postgresql+psycopg://u:p@host/db", "table": "ales_vectors_native", "dim": 1536}
    ]

``kind`` is an outbox ``store_kind`` (or a list of them, or ``"*"``). Optional per-spec keys: ``name``
(report label), ``api_key_env`` (qdrant: env var holding the API key), ``backend`` (pgvector: ``native``
default, or ``portable`` for the JSON-text fallback table). Credentials may live in the URL; prefer
``*_env`` indirection where the backend offers it.

Startup behaviour (fail closed): a malformed spec, a missing ``ales_adapters`` import or a missing
client library for a configured ``type`` raises :class:`ConfigError`. Connections are opened lazily on
the first purge so a store that is briefly down at boot does not stop the control plane; a failed
build is not cached, so the dispatcher's normal retry/backoff covers it.

``ales_adapters`` is an OPTIONAL import (the adapters package lives next to the server in this repo but is
not a hard dependency of it). Deployments that configure purge targets must have it importable.

Verification: every target purges through the adapter's idempotent delete and then re-checks that the
object is really gone. If it is still present the target raises :class:`PurgeVerificationError`, the
registry fails the row, and the outbox retries with backoff. Together with the outbox's at-least-once
delivery this makes purge verified at-least-once. A purge row for a superseded version does not touch (and
verification does not require removal of) a newer version stored under the same ``context_id``.
"""

from __future__ import annotations

import importlib
import json
import logging
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .config import ConfigError

log = logging.getLogger("ales.server.purge")

_KIND_RE = re.compile(r"^[a-z_*]{1,32}$")
_TYPES = ("redis", "qdrant", "pgvector")
_REQUIRED_MODULES = {"redis": "redis", "qdrant": "qdrant_client", "pgvector": "sqlalchemy"}


class PurgeVerificationError(RuntimeError):
    """The purge ran but the object is still present in the store; the outbox row must be retried."""


class _Store:
    """A built backend: ``purge`` (idempotent delete) and ``present`` (is the revoked object still there)."""

    def __init__(self, purge: Callable[[Any], None], present: Callable[[Any], bool]) -> None:
        self.purge = purge
        self.present = present


class VerifiedTarget:
    """Lazy, verified purge target (satisfies ``ales_adapters.purge.PurgeTarget``)."""

    def __init__(self, name: str, builder: Callable[[], _Store]) -> None:
        self.name = name
        self._builder = builder
        self._store_obj: _Store | None = None
        self._lock = threading.Lock()

    def _store(self) -> _Store:
        s = self._store_obj
        if s is None:
            with self._lock:
                if self._store_obj is None:
                    self._store_obj = self._builder()  # raises -> not cached -> retried next attempt
                s = self._store_obj
        return s

    def purge(self, row: Any) -> None:
        s = self._store()
        s.purge(row)
        if s.present(row):
            raise PurgeVerificationError(
                f"{self.name}: object {row.context_id}@{row.version} still present after purge"
            )

    def verify_purge(self, row: Any) -> bool:
        """True when the object is absent from this store (read-only check, no deletion)."""
        return not self._store().present(row)


# ------------------------------------------------------------------------------------- builders
def _build_redis(spec: Mapping[str, Any], ad: Any) -> _Store:
    import redis  # optional dependency

    client = redis.Redis.from_url(spec["url"], decode_responses=True)
    prefix = str(spec.get("prefix", ""))
    inner = ad.CachePurgeTarget(client, prefix=prefix, name=str(spec["name"]))

    def present(row: Any) -> bool:
        idx_raw = client.get(ad.purge.cache_index_key(prefix, row.context_id))
        if idx_raw is not None:
            try:
                rec = json.loads(idx_raw)
                if rec.get("version") not in (None, row.version):
                    return False  # index now describes a newer version; it has its own outbox row
            except (ValueError, TypeError, AttributeError):
                pass
            return True
        return False

    def purge(row: Any) -> None:
        # Read the data key BEFORE the purge drops the reverse index, so the data key itself can be re-checked.
        data_key: str | None = None
        idx_raw = client.get(ad.purge.cache_index_key(prefix, row.context_id))
        if idx_raw is not None:
            try:
                rec = json.loads(idx_raw)
                if rec.get("version") in (None, row.version):
                    data_key = prefix + str(rec["key"])
            except (ValueError, TypeError, KeyError, AttributeError):
                data_key = None
        inner.purge(row)
        if data_key is not None:
            raw = client.get(data_key)
            if raw is not None:
                try:
                    rec = json.loads(raw)
                    still = rec.get("context_id") == row.context_id and rec.get("version") == row.version
                except (ValueError, TypeError, AttributeError):
                    still = False
                if still:
                    # the adapter already dropped the reverse index; put it back so the retry can find the key
                    client.set(ad.purge.cache_index_key(prefix, row.context_id), str(idx_raw))
                    raise PurgeVerificationError(
                        f"{spec['name']}: cache entry for {row.context_id}@{row.version} still present"
                    )

    return _Store(purge, present)


def _build_qdrant(spec: Mapping[str, Any], ad: Any) -> _Store:
    import os

    from qdrant_client import QdrantClient  # optional dependency

    api_key = os.environ.get(str(spec["api_key_env"])) if spec.get("api_key_env") else None
    client = QdrantClient(url=spec["url"], api_key=api_key)
    backend = ad.QdrantBackend(client, collection=str(spec["collection"]))
    inner = ad.VectorPurgeTarget(backend, name=str(spec["name"]))

    def present(row: Any) -> bool:
        if not client.collection_exists(backend.collection):
            return False
        pts = client.retrieve(backend.collection, ids=[ad.qdrant_store.point_id(row.context_id)], with_payload=True)
        if not pts:
            return False
        stored = (pts[0].payload or {}).get("version")
        return stored is None or stored == row.version

    return _Store(inner.purge, present)


def _build_pgvector(spec: Mapping[str, Any], ad: Any) -> _Store:
    from sqlalchemy import create_engine, text

    engine = create_engine(spec["url"], pool_pre_ping=True)
    table = str(spec["table"])
    if spec.get("backend", "native") == "portable":
        backend: Any = ad.PgVectorBackend(engine, table=table)
        q = text(f"SELECT payload FROM {table} WHERE id = :id")

        def stored_version(row: Any) -> tuple[bool, str | None]:
            with engine.connect() as conn:
                r = conn.execute(q, {"id": row.context_id}).fetchone()
            if r is None:
                return False, None
            return True, json.loads(r[0]).get("version")
    else:
        backend = ad.PgVectorNativeBackend(engine, table=table, dim=int(spec["dim"]))
        qn = text(f"SELECT payload->>'version' FROM {table} WHERE id = :id")

        def stored_version(row: Any) -> tuple[bool, str | None]:
            with engine.connect() as conn:
                r = conn.execute(qn, {"id": row.context_id}).fetchone()
            return (False, None) if r is None else (True, r[0])

    inner = ad.VectorPurgeTarget(backend, name=str(spec["name"]))

    def present(row: Any) -> bool:
        exists, ver = stored_version(row)
        return exists and (ver is None or ver == row.version)

    return _Store(inner.purge, present)


_BUILDERS: dict[str, Callable[[Mapping[str, Any], Any], _Store]] = {
    "redis": _build_redis,
    "qdrant": _build_qdrant,
    "pgvector": _build_pgvector,
}


# ------------------------------------------------------------------------------------- parsing
@dataclass(frozen=True)
class PurgeWiring:
    registry: Any  # ales_adapters.PurgeRegistry
    targets: tuple[VerifiedTarget, ...]
    kinds: Mapping[str, tuple[VerifiedTarget, ...]]

    def target_names(self) -> list[str]:
        return sorted({t.name for t in self.targets})

    def verify_purge(self, row: Any) -> bool:
        """True iff the object is absent from every target registered for ``row.store_kind``."""
        wanted = [*self.kinds.get(row.store_kind, ()), *(self.kinds.get("*", ()) if row.store_kind != "*" else ())]
        return all(t.verify_purge(row) for t in wanted)


def _fail(i: int, msg: str) -> ConfigError:
    return ConfigError(f"ALES_PURGE_TARGETS[{i}]: {msg}")


def _parse_spec(i: int, spec: Any) -> tuple[list[str], dict[str, Any]]:
    if not isinstance(spec, dict):
        raise _fail(i, "must be an object")
    typ = spec.get("type")
    if typ not in _TYPES:
        raise _fail(i, f"type must be one of {_TYPES}, got {typ!r}")
    raw_kind = spec.get("kind")
    kinds = [raw_kind] if isinstance(raw_kind, str) else raw_kind
    if not isinstance(kinds, list) or not kinds or not all(isinstance(k, str) and _KIND_RE.match(k) for k in kinds):
        raise _fail(i, "kind must be a store kind string (or non-empty list), e.g. 'chunk', 'cache' or '*'")
    url = spec.get("url")
    if not isinstance(url, str) or not url.strip():
        raise _fail(i, "url is required")
    required = {"redis": (), "qdrant": ("collection",), "pgvector": ("table",)}[typ]
    for key in required:
        if not isinstance(spec.get(key), str) or not spec[key]:
            raise _fail(i, f"{typ} target requires {key!r}")
    if typ == "pgvector":
        if not spec["table"].isidentifier():
            raise _fail(i, "table must be a plain identifier")
        backend = spec.get("backend", "native")
        if backend not in ("native", "portable"):
            raise _fail(i, "backend must be 'native' or 'portable'")
        if backend == "native" and not isinstance(spec.get("dim"), int):
            raise _fail(i, "native pgvector target requires integer 'dim' (the table's vector dimension)")
    if "prefix" in spec and not isinstance(spec["prefix"], str):
        raise _fail(i, "prefix must be a string")
    out = dict(spec)
    out["name"] = str(spec.get("name") or typ)
    return kinds, out


def build_purge_wiring(env: Mapping[str, str]) -> PurgeWiring | None:
    """Parse ``ALES_PURGE_TARGETS``; ``None`` when unset/empty. Raises :class:`ConfigError` on any problem."""
    raw = (env.get("ALES_PURGE_TARGETS") or "").strip()
    if not raw:
        return None
    try:
        specs = json.loads(raw)
    except ValueError as exc:
        raise ConfigError(f"ALES_PURGE_TARGETS is not valid JSON: {exc}") from exc
    if not isinstance(specs, list) or not specs:
        raise ConfigError("ALES_PURGE_TARGETS must be a non-empty JSON list of target objects")
    parsed = [_parse_spec(i, s) for i, s in enumerate(specs)]

    try:  # documented optional import: required as soon as any target is configured
        ad = importlib.import_module("ales_adapters")
        importlib.import_module("ales_adapters.purge")
        importlib.import_module("ales_adapters.qdrant_store")
    except ImportError as exc:
        raise ConfigError(
            "ALES_PURGE_TARGETS is set but the optional 'ales_adapters' package cannot be imported "
            f"({exc}); install/mount adapters/ alongside the server"
        ) from exc
    for i, (_, spec) in enumerate(parsed):
        mod = _REQUIRED_MODULES[spec["type"]]
        try:
            importlib.import_module(mod)
        except ImportError as exc:
            raise _fail(i, f"type {spec['type']!r} needs the {mod!r} package, which is not installed") from exc

    registry = ad.PurgeRegistry()
    targets: list[VerifiedTarget] = []
    by_kind: dict[str, list[VerifiedTarget]] = {}
    for kinds, spec in parsed:
        builder = _BUILDERS[spec["type"]]

        def make(builder: Callable[[Mapping[str, Any], Any], _Store] = builder, spec: dict[str, Any] = spec) -> _Store:
            return builder(spec, ad)

        target = VerifiedTarget(spec["name"], make)
        targets.append(target)
        for k in kinds:
            registry.register(k, target)
            by_kind.setdefault(k, []).append(target)
    return PurgeWiring(registry, tuple(targets), {k: tuple(v) for k, v in by_kind.items()})
