"""Guarded vector store.

``GuardedVectorStore`` wraps any backend exposing ``add(id, vector, payload)`` and
``search(vector, k) -> [(id, score, payload)]``. Chunks are registered as derivatives of their parent
envelopes on write, and every search result is filtered through ``guard_retrieval`` on read.

``PgVectorBackend`` stores vectors as JSON lists in a plain SQL table and computes cosine similarity
in Python, so it works on any SQLAlchemy engine (Postgres, SQLite) without the pgvector extension.
Real pgvector is a drop-in: implement the same two methods with ``embedding <=> :v`` ordering in SQL.
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


class PgVectorBackend:
    """SQLAlchemy-backed store; vector kept as a JSON list, cosine computed in Python."""

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

    def search(self, vector: Sequence[float], k: int) -> list[tuple[str, float, dict[str, Any]]]:
        with self.engine.connect() as conn:
            rows = conn.execute(self._text(f"SELECT id, vector, payload FROM {self.table}")).fetchall()
        scored = [(r[0], cosine(vector, json.loads(r[1])), json.loads(r[2])) for r in rows]
        scored.sort(key=lambda t: t[1], reverse=True)
        return scored[:k]


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
