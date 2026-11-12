"""Guarded vector store.

``GuardedVectorStore`` wraps any backend exposing ``add(id, vector, payload)`` and
``search(vector, k) -> [(id, score, payload)]``. Chunks are registered as derivatives of their parent
envelopes on write, and every search result is filtered through ``guard_retrieval`` on read.

Two Postgres-family backends live here, and the difference matters:

* ``PgVectorBackend`` is a PORTABLE FALLBACK. It is NOT the pgvector extension: vectors are JSON text in
  a plain table and cosine similarity is computed in Python after reading every row (O(n) per search,
  no index). It exists so the guarded flow runs on any SQLAlchemy engine, including SQLite in tests.
* ``PgVectorNativeBackend`` uses the real pgvector extension: ``vector(n)`` column, ``<=>`` cosine
  distance computed and ordered in the database, optional hnsw/ivfflat index. Needs PostgreSQL with the
  extension available (e.g. the ``pgvector/pgvector`` image) and the ``pgvector`` Python package.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from ales_sdk.client import InvariantClient
from ales_sdk.envelope import new_derivative
from ales_sdk.wrappers import Blocked, guard_retrieval


class VectorBackend(Protocol):
    def add(self, id: str, vector: Sequence[float], payload: dict[str, Any]) -> None: ...

    def search(self, vector: Sequence[float], k: int) -> list[tuple[str, float, dict[str, Any]]]: ...

    def delete(self, id: str, *, version: str | None = None) -> None:
        """Idempotent physical delete; a missing id is success. With ``version``, only delete if the
        stored payload is that version (or carries none), so a stale purge cannot remove a newer write."""


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class InMemoryVectorBackend:
    def __init__(self) -> None:
        self._rows: dict[str, tuple[list[float], dict[str, Any]]] = {}

    def add(self, id: str, vector: Sequence[float], payload: dict[str, Any]) -> None:
        self._rows[id] = (list(vector), dict(payload))

    def search(self, vector: Sequence[float], k: int) -> list[tuple[str, float, dict[str, Any]]]:
        scored = [(i, cosine(vector, v), p) for i, (v, p) in self._rows.items()]
        scored.sort(key=lambda t: t[1], reverse=True)
        return scored[:k]

    def delete(self, id: str, *, version: str | None = None) -> None:
        row = self._rows.get(id)
        if row is None:
            return
        stored = row[1].get("version")
        if version is not None and stored is not None and stored != version:
            return
        self._rows.pop(id, None)


class PgVectorBackend:
    """Portable fallback, NOT the pgvector extension.

    Vectors are stored as JSON text in an ordinary table and cosine similarity is computed in Python
    over every row, so it works on any SQLAlchemy engine (SQLite, Postgres) but does not scale and is
    not pgvector. Use ``PgVectorNativeBackend`` for the real extension.
    """

    def __init__(self, engine: Any, table: str = "ales_vectors") -> None:
        from sqlalchemy import text  # optional dependency, imported lazily

        if not table.isidentifier():
            raise ValueError("invalid table name")
        self._text = text
        self.engine = engine
        self.table = table
        with engine.begin() as conn:
            conn.execute(
                text(
                    f"CREATE TABLE IF NOT EXISTS {table} "
                    "(id VARCHAR(64) PRIMARY KEY, vector TEXT NOT NULL, payload TEXT NOT NULL)"
                )
            )

    def add(self, id: str, vector: Sequence[float], payload: dict[str, Any]) -> None:
        t = self._text
        with self.engine.begin() as conn:
            conn.execute(t(f"DELETE FROM {self.table} WHERE id = :id"), {"id": id})
            conn.execute(
                t(f"INSERT INTO {self.table} (id, vector, payload) VALUES (:id, :v, :p)"),
                {"id": id, "v": json.dumps(list(vector)), "p": json.dumps(payload)},
            )

    def delete(self, id: str, *, version: str | None = None) -> None:
        t = self._text
        with self.engine.begin() as conn:
            if version is not None:
                row = conn.execute(t(f"SELECT payload FROM {self.table} WHERE id = :id"), {"id": id}).fetchone()
                if row is None:
                    return
                stored = json.loads(row[0]).get("version")
                if stored is not None and stored != version:
                    return
            conn.execute(t(f"DELETE FROM {self.table} WHERE id = :id"), {"id": id})

    def search(self, vector: Sequence[float], k: int) -> list[tuple[str, float, dict[str, Any]]]:
        with self.engine.connect() as conn:
            rows = conn.execute(self._text(f"SELECT id, vector, payload FROM {self.table}")).fetchall()
        scored = [(r[0], cosine(vector, json.loads(r[1])), json.loads(r[2])) for r in rows]
        scored.sort(key=lambda t: t[1], reverse=True)
        return scored[:k]


class PgVectorNativeBackend:
    """Real pgvector: ``vector(dim)`` column, cosine via the ``<=>`` operator, ranking done in Postgres.

    ``engine`` must be a PostgreSQL SQLAlchemy engine whose server has the pgvector extension available;
    ``CREATE EXTENSION IF NOT EXISTS vector`` is issued on construction (needs the privilege to do so).
    ``index`` may be ``None`` (default, exact scan), ``"hnsw"`` or ``"ivfflat"`` (cosine ops). The payload
    is JSONB, which lets version-aware delete be a single atomic ``DELETE ... WHERE`` with no race.
    Scores are cosine similarity (``1 - distance``), matching the other backends.
    """

    def __init__(
        self, engine: Any, table: str = "ales_vectors_native", dim: int = 3, index: str | None = None
    ) -> None:
        from pgvector.sqlalchemy import Vector  # optional dependencies, imported lazily
        from sqlalchemy import Column, MetaData, String, Table, text
        from sqlalchemy.dialects.postgresql import JSONB

        if not table.isidentifier():
            raise ValueError("invalid table name")
        if index not in (None, "hnsw", "ivfflat"):
            raise ValueError("index must be None, 'hnsw' or 'ivfflat'")
        self.engine, self.table, self.dim = engine, table, dim
        self._text = text
        with engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        md = MetaData()
        self._t = Table(
            table,
            md,
            Column("id", String(128), primary_key=True),
            Column("embedding", Vector(dim), nullable=False),
            Column("payload", JSONB, nullable=False),
        )
        md.create_all(engine)
        if index:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        f"CREATE INDEX IF NOT EXISTS {table}_{index}_idx ON {table} "
                        f"USING {index} (embedding vector_cosine_ops)"
                    )
                )

    def add(self, id: str, vector: Sequence[float], payload: dict[str, Any]) -> None:
        from sqlalchemy.dialects.postgresql import insert

        vec = [float(x) for x in vector]
        if len(vec) != self.dim:
            raise ValueError(f"vector dimension {len(vec)} != column dimension {self.dim}")
        stmt = insert(self._t).values(id=id, embedding=vec, payload=payload)
        stmt = stmt.on_conflict_do_update(
            index_elements=["id"],
            set_={"embedding": stmt.excluded.embedding, "payload": stmt.excluded.payload},
        )
        with self.engine.begin() as conn:
            conn.execute(stmt)

    def search(self, vector: Sequence[float], k: int) -> list[tuple[str, float, dict[str, Any]]]:
        from sqlalchemy import select

        dist = self._t.c.embedding.cosine_distance([float(x) for x in vector])
        stmt = select(self._t.c.id, dist.label("d"), self._t.c.payload).order_by(dist).limit(k)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()
        return [(r[0], 1.0 - float(r[1]), dict(r[2])) for r in rows]

    def delete(self, id: str, *, version: str | None = None) -> None:
        t = self._text
        with self.engine.begin() as conn:
            if version is None:
                conn.execute(t(f"DELETE FROM {self.table} WHERE id = :id"), {"id": id})
            else:  # one atomic statement: a stale purge cannot delete a newer version
                conn.execute(
                    t(
                        f"DELETE FROM {self.table} WHERE id = :id "
                        "AND (payload->>'version' IS NULL OR payload->>'version' = :v)"
                    ),
                    {"id": id, "v": version},
                )

    def count(self) -> int:
        with self.engine.connect() as conn:
            return int(conn.execute(self._text(f"SELECT count(*) FROM {self.table}")).scalar_one())

    def contains(self, id: str) -> bool:
        q = self._text(f"SELECT 1 FROM {self.table} WHERE id = :id")
        with self.engine.connect() as conn:
            return conn.execute(q, {"id": id}).first() is not None

    def drop(self) -> None:
        with self.engine.begin() as conn:
            conn.execute(self._text(f"DROP TABLE IF EXISTS {self.table}"))


@dataclass
class SearchHit:
    id: str
    score: float
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def context_id(self) -> str:
        return str(self.payload["context_id"])

    @property
    def version(self) -> str | None:
        return self.payload.get("version")


class GuardedVectorStore:
    def __init__(
        self,
        client: InvariantClient,
        principal: Mapping[str, str],
        purpose: str,
        backend: VectorBackend,
    ) -> None:
        self.client = client
        self.principal = principal
        self.purpose = purpose
        self.backend = backend

    def add_derived(
        self,
        parent_envelopes: Iterable[Mapping[str, Any]],
        text: str,
        vector: Sequence[float],
        *,
        kind: str = "chunk",
        object_id: str | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Register a derivative of ``parent_envelopes`` and store it. Returns the new envelope."""
        env = new_derivative(
            kind,
            parent_envelopes,
            self.client.tenant_id,
            object_id or f"{kind}:{text[:40]}",
            text,
            source_system="vector-store",
        )
        self.client.register_derivation(env)
        stored = {
            **(payload or {}),
            "text": text,
            "context_id": env["context_id"],
            "version": env["object_version"],
        }
        self.backend.add(env["context_id"], vector, stored)
        return env

    def search(
        self,
        vector: Sequence[float],
        k: int = 5,
        *,
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> tuple[list[SearchHit], list[Blocked]]:
        """Return ``(allowed, blocked)``. Blocked hits are never part of ``allowed``."""
        hits = [SearchHit(i, s, p) for i, s, p in self.backend.search(vector, k)]
        return guard_retrieval(
            self.client,
            self.principal,
            self.purpose,
            hits,
            lambda h: h.context_id,
            version_getter=lambda h: h.version,
            classification_getter=lambda h: h.payload.get("classification"),
            session_id=session_id,
            agent_id=agent_id,
        )
