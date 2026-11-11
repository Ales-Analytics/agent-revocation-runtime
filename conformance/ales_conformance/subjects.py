"""Testbed (in-process control plane) and Subject wrappers for the in-repo adapters."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Self

import httpx
from ales_adapters.fs_source import FilesystemSourceConnector
from ales_adapters.langgraph_middleware import guard_node
from ales_adapters.pgvector_store import GuardedVectorStore, InMemoryVectorBackend
from ales_adapters.redis_cache import DictRedis, GuardedCache
from ales_sdk import InvariantClient, new_derivative
from ales_server import create_app
from fastapi.testclient import TestClient

from .contract import ObjectRef, ReadOutcome

PURPOSE = "conformance"


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
        self._tc = TestClient(create_app("sqlite://"))
        self._tc.__enter__()
        self.client = InvariantClient("http://testserver", tenant, transport=_Bridge(self._tc))

    def close(self) -> None:
        self.client.close()
        self._tc.__exit__(None, None, None)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class VectorStoreSubject:
    name = "GuardedVectorStore (InMemory backend)"

    def __init__(self, client: InvariantClient) -> None:
        self.client = client
        self.backend = InMemoryVectorBackend()
        self._n = 0

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

    def __init__(self, client: InvariantClient) -> None:
        self.client = client
        self.redis = DictRedis()
        self._n = 0

    def ingest(self, parents: Sequence[Mapping[str, Any]]) -> ObjectRef:
        self._n += 1
        key = f"k{self._n}"
        GuardedCache(self.client, {"type": "user", "id": "x"}, PURPOSE, self.redis).put(
            key, {"answer": key}, parents
        )
        return ObjectRef(key, handle=key)

    def read(self, ref: ObjectRef, principal: Mapping[str, str]) -> ReadOutcome:
        value, blocked = GuardedCache(self.client, principal, PURPOSE, self.redis).get(ref.handle)
        if value is not None:
            return ReadOutcome(value)
        if blocked:
            return ReadOutcome(None, True, list(blocked[0].reasons))
        return ReadOutcome(None)


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
        doc = {
            "context_id": env["context_id"],
            "version": env["object_version"],
            "text": f"lg text {self._n}",
        }
        return ObjectRef(env["context_id"], handle=doc)

    def read(self, ref: ObjectRef, principal: Mapping[str, str]) -> ReadOutcome:
        doc = ref.handle

        @guard_node(
            self.client, principal, PURPOSE, lambda d: d["context_id"], version_getter=lambda d: d["version"]
        )
        def fake_retrieve_node(state: Mapping[str, Any]) -> dict[str, Any]:
            return {"documents": [doc]}

        out = fake_retrieve_node({})
        if out.get("documents"):
            return ReadOutcome(out["documents"][0]["text"])
        blocked = out.get("ales_blocked") or []
        if blocked:
            return ReadOutcome(None, True, list(blocked[0]["reasons"]))
        return ReadOutcome(None)


def fs_factory(client: InvariantClient, base: Path) -> FilesystemSourceConnector:
    return FilesystemSourceConnector(
        client, base / "root", client.tenant_id, checkpoint_path=base / "ck.json"
    )
