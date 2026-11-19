"""Testbed (in-process control plane) and Subject wrappers for the in-repo adapters."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Self

import httpx
from ales_adapters.acs_adapter import AcsContextGuard
from ales_adapters.fs_source import FilesystemSourceConnector
from ales_adapters.langgraph_middleware import guard_node
from ales_adapters.live_stores import pg_engine, qdrant_client, redis_client
from ales_adapters.llamaindex_adapter import GuardedLlamaRetriever, IngestionCallback
from ales_adapters.pgvector_store import GuardedVectorStore, InMemoryVectorBackend, PgVectorNativeBackend
from ales_adapters.purge import CachePurgeTarget, PurgeRegistry, VectorPurgeTarget
from ales_adapters.qdrant_store import QdrantBackend
from ales_adapters.redis_cache import DictRedis, GuardedCache
from ales_core import OutboxDispatcher
from ales_sdk import InvariantClient, new_derivative
from ales_server import create_app
from fastapi.testclient import TestClient

from .contract import ObjectRef, ReadOutcome

PURPOSE = "conformance"
# In-process testbed only: the token map below is created per Testbed and never leaves the process.
TESTBED_TOKEN = "conformance-testbed-token"


class _Bridge(httpx.BaseTransport):
    def __init__(self, tc: TestClient) -> None:
        self.tc = tc

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
        r = self.tc.request(request.method, str(request.url), content=request.content, headers=headers)
        hdrs = [
            (k, v)
            for k, v in r.headers.items()
            if k.lower() not in ("content-encoding", "transfer-encoding", "content-length")
        ]
        return httpx.Response(r.status_code, headers=hdrs, content=r.content, request=request)


class Testbed:
    """Fresh in-memory control plane and a bridged client."""

    def __init__(self, tenant: str = "conformance") -> None:
        tokens = {
            TESTBED_TOKEN: {
                "tenant_id": tenant,
                "roles": ["ingest", "revoke", "read", "admin"],
                "subject": "conformance",
            }
        }
        self.app = create_app("sqlite://", tokens=tokens, outbox_interval=0)
        self._tc = TestClient(self.app)
        self._tc.__enter__()
        self.client = InvariantClient(
            "http://testserver", tenant, auth_token=TESTBED_TOKEN, transport=_Bridge(self._tc)
        )

    def dispatcher(self, registry: PurgeRegistry) -> OutboxDispatcher:
        """A dispatcher over this testbed's outbox with real purge handlers (driven by ``run_once``)."""
        return OutboxDispatcher(self.app.state.session_factory, registry.as_outbox_handlers())

    def close(self) -> None:
        self.client.close()
        self._tc.__exit__(None, None, None)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class VectorStoreSubject:
    name = "GuardedVectorStore (InMemory backend)"
    store_kind = "in-memory"

    def __init__(
        self,
        client: InvariantClient,
        testbed: Testbed | None = None,
        *,
        backend: Any = None,
        contains: Callable[[str], bool] | None = None,
    ) -> None:
        self.client = client
        self.backend = backend if backend is not None else InMemoryVectorBackend()
        self._contains = contains
        self._n = 0
        # With a testbed the subject also takes part in the physical-purge check (f).
        self.supports_purge = testbed is not None
        self._dispatcher = (
            testbed.dispatcher(PurgeRegistry().register("chunk", VectorPurgeTarget(self.backend)))
            if testbed
            else None
        )

    def purge(self) -> None:
        assert self._dispatcher is not None
        self._dispatcher.run_once()

    def raw_contains(self, ref: ObjectRef) -> bool:
        """Bypass the guard: look in the backend's own storage."""
        if self._contains is not None:
            return self._contains(ref.context_id)
        return ref.context_id in self.backend._rows

    def close(self) -> None:
        """Remove any live-store artefacts (no-op for the in-memory backend)."""

    def ingest(self, parents: Sequence[Mapping[str, Any]]) -> ObjectRef:
        self._n += 1
        store = GuardedVectorStore(self.client, {"type": "user", "id": "x"}, PURPOSE, self.backend)
        env = store.add_derived(parents, f"chunk text {self._n}", [1.0, float(self._n)])
        return ObjectRef(env["context_id"], handle=[1.0, float(self._n)])

    def read(self, ref: ObjectRef, principal: Mapping[str, str]) -> ReadOutcome:
        store = GuardedVectorStore(self.client, principal, PURPOSE, self.backend)
        allowed, blocked = store.search(ref.handle, k=10)
        for h in allowed:
            if h.context_id == ref.context_id:
                return ReadOutcome(h.payload["text"])
        for b in blocked:
            if b.context_id == ref.context_id:
                return ReadOutcome(None, True, list(b.reasons))
        return ReadOutcome(None)


class CacheSubject:
    name = "GuardedCache (DictRedis)"
    store_kind = "in-memory"

    def __init__(
        self,
        client: InvariantClient,
        testbed: Testbed | None = None,
        *,
        redis_like: Any = None,
        prefix: str = "",
    ) -> None:
        self.client = client
        self.redis = redis_like if redis_like is not None else DictRedis()
        self.prefix = prefix
        self._n = 0
        self._ctx: dict[str, str] = {}
        self.supports_purge = testbed is not None
        prefix = self.prefix
        self._dispatcher = (
            testbed.dispatcher(PurgeRegistry().register("cache", CachePurgeTarget(self.redis, prefix=prefix)))
            if testbed
            else None
        )

    def purge(self) -> None:
        assert self._dispatcher is not None
        self._dispatcher.run_once()

    def raw_contains(self, ref: ObjectRef) -> bool:
        """Bypass the guard: the cache entry or its reverse-index record is still in the raw store."""
        if isinstance(self.redis, DictRedis):
            return (
                self.prefix + ref.handle in self.redis.data
                or f"{self.prefix}__ales_idx__{self._ctx[ref.handle]}" in self.redis.data
            )
        return bool(
            self.redis.exists(self.prefix + ref.handle)
            or self.redis.exists(f"{self.prefix}__ales_idx__{self._ctx[ref.handle]}")
        )

    def close(self) -> None:
        """Remove any live-store keys written under this subject's prefix."""
        if self.prefix and not isinstance(self.redis, DictRedis):
            keys = list(self.redis.scan_iter(match=f"{self.prefix}*"))
            if keys:
                self.redis.delete(*keys)

    def ingest(self, parents: Sequence[Mapping[str, Any]]) -> ObjectRef:
        self._n += 1
        key = f"k{self._n}"
        env = GuardedCache(self.client, {"type": "user", "id": "x"}, PURPOSE, self.redis, self.prefix).put(
            key, {"answer": key}, parents
        )
        self._ctx[key] = env["context_id"]
        return ObjectRef(key, handle=key)

    def read(self, ref: ObjectRef, principal: Mapping[str, str]) -> ReadOutcome:
        value, blocked = GuardedCache(self.client, principal, PURPOSE, self.redis, self.prefix).get(
            ref.handle
        )
        if value is not None:
            return ReadOutcome(value)
        if blocked:
            return ReadOutcome(None, True, list(blocked[0].reasons))
        return ReadOutcome(None)


def _live_id() -> str:
    return "ales_c_" + uuid.uuid4().hex[:12]


class QdrantSubject(VectorStoreSubject):
    name = "GuardedVectorStore (Qdrant, live)"
    store_kind = "live store"

    def __init__(self, client: InvariantClient, testbed: Testbed | None = None) -> None:
        self._qb = QdrantBackend(qdrant_client(), _live_id(), dim=2)
        super().__init__(client, testbed, backend=self._qb, contains=self._qb.contains)

    def close(self) -> None:
        self._qb.drop()


class PgVectorNativeSubject(VectorStoreSubject):
    name = "GuardedVectorStore (pgvector native, live)"
    store_kind = "live store"

    def __init__(self, client: InvariantClient, testbed: Testbed | None = None) -> None:
        self._pb = PgVectorNativeBackend(pg_engine(), _live_id(), dim=2)
        super().__init__(client, testbed, backend=self._pb, contains=self._pb.contains)

    def close(self) -> None:
        self._pb.drop()
        self._pb.engine.dispose()


class RedisCacheSubject(CacheSubject):
    name = "GuardedCache (Redis, live)"
    store_kind = "live store"

    def __init__(self, client: InvariantClient, testbed: Testbed | None = None) -> None:
        super().__init__(client, testbed, redis_like=redis_client(), prefix=f"{_live_id()}:")


class LangGraphSubject:
    name = "langgraph guard_node (fake node)"

    def __init__(self, client: InvariantClient) -> None:
        self.client = client
        self._n = 0

    def ingest(self, parents: Sequence[Mapping[str, Any]]) -> ObjectRef:
        self._n += 1
        env = new_derivative(
            "chunk", parents, self.client.tenant_id, f"lg-chunk-{self._n}", f"lg text {self._n}"
        )
        self.client.register_derivation(env)
        document = {
            "context_id": env["context_id"],
            "version": env["object_version"],
            "text": f"lg text {self._n}",
        }
        return ObjectRef(env["context_id"], handle=document)

    def read(self, ref: ObjectRef, principal: Mapping[str, str]) -> ReadOutcome:
        document = ref.handle

        @guard_node(
            self.client, principal, PURPOSE, lambda d: d["context_id"], version_getter=lambda d: d["version"]
        )
        def fake_retrieve_node(state: Mapping[str, Any]) -> dict[str, Any]:
            return {"documents": [document]}

        result = fake_retrieve_node({})
        if result.get("documents"):
            return ReadOutcome(result["documents"][0]["text"])
        blocked = result.get("ales_blocked") or []
        if blocked:
            return ReadOutcome(None, True, list(blocked[0]["reasons"]))
        return ReadOutcome(None)


def fs_factory(client: InvariantClient, base: Path) -> FilesystemSourceConnector:
    return FilesystemSourceConnector(
        client, base / "root", client.tenant_id, checkpoint_path=base / "ck.json"
    )


class _DictStorePurgeTarget:
    """Purge target for the dict-backed fake stores used by the framework-adapter subjects."""

    name = "dict-store"

    def __init__(self, store: dict[str, Any]) -> None:
        self.store = store

    def purge(self, row: Any) -> None:
        entry = self.store.get(row.context_id)
        if entry is not None and entry["version"] == row.version:
            del self.store[row.context_id]


class _FakeNode:
    """Minimal LlamaIndex TextNode stand-in (metadata dict + get_content)."""

    def __init__(self, node_id: str, text: str) -> None:
        self.node_id = node_id
        self.metadata: dict[str, Any] = {}
        self._text = text

    def get_content(self) -> str:
        return self._text


class _FakeNodeWithScore:
    def __init__(self, node: _FakeNode) -> None:
        self.node = node
        self.score = 1.0


class _FakeRetriever:
    """Returns every stored node (a stand-in for similarity search over a backing store)."""

    def __init__(self, store: dict[str, Any]) -> None:
        self.store = store

    def retrieve(self, query: str) -> list[_FakeNodeWithScore]:
        return [_FakeNodeWithScore(e["node"]) for e in list(self.store.values())]


class _StoreSubjectBase:
    store_kind = "in-memory"
    name = "base"

    def __init__(self, client: InvariantClient, testbed: Testbed | None = None) -> None:
        self.client = client
        self.store: dict[str, Any] = {}
        self._n = 0
        self.supports_purge = testbed is not None
        self._dispatcher = (
            testbed.dispatcher(PurgeRegistry().register("chunk", _DictStorePurgeTarget(self.store)))
            if testbed
            else None
        )

    def purge(self) -> None:
        assert self._dispatcher is not None
        self._dispatcher.run_once()

    def raw_contains(self, ref: ObjectRef) -> bool:
        return ref.context_id in self.store


class LlamaIndexSubject(_StoreSubjectBase):
    name = "GuardedLlamaRetriever (fake retriever)"

    def ingest(self, parents: Sequence[Mapping[str, Any]]) -> ObjectRef:
        self._n += 1
        node = _FakeNode(f"li-node-{self._n}", f"li text {self._n}")
        IngestionCallback(self.client)(list(parents), [node])
        context_id = node.metadata["ales_context_id"]
        self.store[context_id] = {"node": node, "version": node.metadata["ales_version"]}
        return ObjectRef(context_id)

    def read(self, ref: ObjectRef, principal: Mapping[str, str]) -> ReadOutcome:
        g = GuardedLlamaRetriever(self.client, principal, PURPOSE, _FakeRetriever(self.store))
        allowed, blocked = g.retrieve("q")
        for n in allowed:
            if n.node.metadata["ales_context_id"] == ref.context_id:
                return ReadOutcome(n.node.get_content())
        for b in blocked:
            if b.context_id == ref.context_id:
                return ReadOutcome(None, True, list(b.reasons))
        return ReadOutcome(None)


class AcsRetrievalSubject(_StoreSubjectBase):
    name = "AcsContextGuard (after_knowledge_retrieval)"

    def ingest(self, parents: Sequence[Mapping[str, Any]]) -> ObjectRef:
        self._n += 1
        env = new_derivative(
            "chunk", parents, self.client.tenant_id, f"acs-chunk-{self._n}", f"acs text {self._n}"
        )
        self.client.register_derivation(env)
        self.store[env["context_id"]] = {
            "version": env["object_version"],
            "doc": {
                "context_id": env["context_id"],
                "version": env["object_version"],
                "text": f"acs text {self._n}",
            },
        }
        return ObjectRef(env["context_id"])

    def read(self, ref: ObjectRef, principal: Mapping[str, str]) -> ReadOutcome:
        guard = AcsContextGuard(self.client)
        context = {
            "tenant": self.client.tenant_id,
            "principal": dict(principal),
            "purpose": PURPOSE,
            "session_id": "conformance-session",
            "agent_id": "conformance-agent",
        }
        d = guard.handle(
            "after_knowledge_retrieval", {"ctx": context, "results": [e["doc"] for e in self.store.values()]}
        )
        if not d.allow:
            return ReadOutcome(None, True, list(d.reasons))
        for document in d.data["results"]:
            if document["context_id"] == ref.context_id:
                return ReadOutcome(document["text"])
        for b in d.data.get("blocked", []):
            if b["context_id"] == ref.context_id:
                return ReadOutcome(None, True, list(b["reasons"]))
        return ReadOutcome(None)
