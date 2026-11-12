"""Qdrant-backed ``VectorBackend`` (real vector database, cosine distance).

Qdrant point ids must be unsigned ints or UUIDs, while ALES ``context_id``s are arbitrary strings, so the
point id is a deterministic UUID5 of the ``context_id`` and the original id is kept in the payload under
``_ales_id``. Writes and deletes use ``wait=True`` so a returned call means the change is applied, which
the physical-purge guarantee relies on.

Version-aware delete is a single server-side filtered delete (point id AND (payload ``version`` equals
the purged version OR ``version`` is absent)), so a stale purge racing a newer write cannot remove the
newer row: there is no read-then-delete window.

Requires the ``qdrant-client`` package (optional dependency, imported lazily).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

_NAMESPACE = uuid.UUID("6f1c3a52-7a54-4b0e-9c1e-5b1f0a1e5a1e")
ID_FIELD = "_ales_id"


def point_id(id: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, id))


class QdrantBackend:
    """One Qdrant collection per instance. ``client`` is a ``qdrant_client.QdrantClient``.

    ``dim`` fixes the vector size up front; when omitted the collection is created lazily on the first
    ``add`` with that vector's length. An existing collection is reused as-is.
    """

    def __init__(self, client: Any, collection: str = "ales_vectors", dim: int | None = None) -> None:
        from qdrant_client import models  # optional dependency, imported lazily

        self._m = models
        self.client = client
        self.collection = collection
        self._dim = dim
        if dim is not None:
            self._ensure(dim)
        elif client.collection_exists(collection):
            self._dim = -1  # exists; size unknown but already configured

    def _ensure(self, dim: int) -> None:
        if self._dim is not None and self._dim != dim and self._dim != -1:
            raise ValueError(f"vector dimension {dim} != collection dimension {self._dim}")
        if self.client.collection_exists(self.collection):
            self._dim = dim if self._dim is None else self._dim
            return
        self.client.create_collection(
            self.collection,
            vectors_config=self._m.VectorParams(size=dim, distance=self._m.Distance.COSINE),
        )
        self._dim = dim

    def add(self, id: str, vector: Sequence[float], payload: dict[str, Any]) -> None:
        if self._dim is None:
            self._ensure(len(vector))
        point = self._m.PointStruct(
            id=point_id(id), vector=[float(x) for x in vector], payload={**payload, ID_FIELD: id}
        )
        self.client.upsert(self.collection, points=[point], wait=True)

    def search(self, vector: Sequence[float], k: int) -> list[tuple[str, float, dict[str, Any]]]:
        if not self.client.collection_exists(self.collection):
            return []
        res = self.client.query_points(
            self.collection, query=[float(x) for x in vector], limit=k, with_payload=True
        )
        out: list[tuple[str, float, dict[str, Any]]] = []
        for p in res.points:
            payload = dict(p.payload or {})
            out.append((str(payload.pop(ID_FIELD)), float(p.score), payload))
        return out

    def delete(self, id: str, *, version: str | None = None) -> None:
        if not self.client.collection_exists(self.collection):
            return  # never stored here: success
        m = self._m
        must: list[Any] = [m.HasIdCondition(has_id=[point_id(id)])]
        if version is not None:
            must.append(
                m.Filter(
                    should=[
                        m.FieldCondition(key="version", match=m.MatchValue(value=version)),
                        m.IsEmptyCondition(is_empty=m.PayloadField(key="version")),
                        m.IsNullCondition(is_null=m.PayloadField(key="version")),
                    ]
                )
            )
        self.client.delete(
            self.collection, points_selector=m.FilterSelector(filter=m.Filter(must=must)), wait=True
        )

    def count(self) -> int:
        """Exact number of points (raw-store inspection, used by tests and conformance)."""
        if not self.client.collection_exists(self.collection):
            return 0
        return int(self.client.count(self.collection, exact=True).count)

    def contains(self, id: str) -> bool:
        if not self.client.collection_exists(self.collection):
            return False
        return bool(self.client.retrieve(self.collection, ids=[point_id(id)], with_payload=False))

    def drop(self) -> None:
        self.client.delete_collection(self.collection)
