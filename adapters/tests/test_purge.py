"""Physical purge: unit behaviour of the targets/registry and the crash-safe end-to-end flow."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from ales_adapters import (
    CachePurgeTarget,
    DictRedis,
    GuardedCache,
    GuardedVectorStore,
    InMemoryVectorBackend,
    PgVectorBackend,
    PurgeError,
    PurgeRegistry,
    VectorPurgeTarget,
)
from ales_core import OutboxDispatcher, outbox_stats
from ales_sdk import InvariantClient, new_source
from ales_server import create_app
from fastapi.testclient import TestClient

U = {"type": "user", "id": "alice"}


def row(kind: str, cid: str, version: str = "1") -> SimpleNamespace:
    return SimpleNamespace(tenant_id="t1", context_id=cid, version=version, store_kind=kind)


# ------------------------------------------------------------------------------ vector backends
def _backends(tmp_path):
    from sqlalchemy import create_engine

    return [InMemoryVectorBackend(), PgVectorBackend(create_engine(f"sqlite:///{tmp_path / 'v.db'}"))]


def test_vector_backend_delete_is_idempotent_and_version_aware(tmp_path):
    for b in _backends(tmp_path):
        b.add("c1", [1.0, 0.0], {"context_id": "c1", "version": "2"})
        b.add("c2", [0.0, 1.0], {"context_id": "c2", "version": "1"})
        b.delete("missing")  # absent id is success
        b.delete("c1", version="1")  # stale purge must not remove the newer version
        assert {h[0] for h in b.search([1.0, 0.0], 10)} == {"c1", "c2"}
        b.delete("c1", version="2")
        b.delete("c1", version="2")  # second delete: still success
        assert {h[0] for h in b.search([1.0, 0.0], 10)} == {"c2"}
        b.delete("c2")  # unversioned delete always removes
        assert b.search([1.0, 0.0], 10) == []


# ------------------------------------------------------------------------------ cache target
def test_cache_purge_removes_entry_and_index_and_is_idempotent(client, src):
    r = DictRedis()
    cache = GuardedCache(client, U, "support", r, prefix="p:")
    env = cache.put("q", {"a": 1}, [src])
    idx = f"p:__ales_idx__{env['context_id']}"
    assert json.loads(r.data[idx]) == {"key": "q", "version": env["object_version"]}

    t = CachePurgeTarget(r, prefix="p:")
    rw = row("cache", env["context_id"], env["object_version"])
    t.purge(rw)
    assert r.data == {}
    t.purge(rw)  # never-in-store / already purged: success
    t.purge(row("cache", "no-such-context"))


def test_cache_purge_skips_newer_version_under_same_key(client, src):
    r = DictRedis()
    cache = GuardedCache(client, U, "support", r)
    env = cache.put("q", 1, [src])
    t = CachePurgeTarget(r)
    t.purge(row("cache", env["context_id"], "not-the-stored-version"))
    assert "q" in r.data  # untouched


def test_cache_purge_partial_failure_is_rerunnable(client, src):
    class FlakyIndexDelete(DictRedis):
        fail = True

        def delete(self, *keys):
            if self.fail and any("__ales_idx__" in k for k in keys):
                raise RuntimeError("redis blip")
            return super().delete(*keys)

    r = FlakyIndexDelete()
    env = GuardedCache(client, U, "s", r).put("q", 1, [src])
    t = CachePurgeTarget(r)
    rw = row("cache", env["context_id"], env["object_version"])
    with pytest.raises(RuntimeError):
        t.purge(rw)
    assert "q" not in r.data and any("__ales_idx__" in k for k in r.data)  # data gone, index kept for retry
    r.fail = False
    t.purge(rw)
    assert r.data == {}


# ------------------------------------------------------------------------------ registry
def test_registry_runs_all_targets_then_raises_and_wildcard_applies():
    calls: list[str] = []

    class T:
        def __init__(self, name, fail=False):
            self.name, self.fail = name, fail

        def purge(self, rw):
            calls.append(f"{self.name}:{rw.context_id}")
            if self.fail:
                raise RuntimeError("boom")

    reg = PurgeRegistry()
    reg.register("chunk", T("a", fail=True)).register("chunk", T("b")).register("*", T("any"))
    with pytest.raises(PurgeError) as ei:
        reg.purge(row("chunk", "x"))
    assert calls == ["a:x", "b:x", "any:x"] and [n for n, _ in ei.value.failures] == ["a"]
    calls.clear()
    reg.purge(row("memory", "y"))  # only the wildcard target applies
    assert calls == ["any:y"]

    handlers = reg.as_outbox_handlers()
    assert set(handlers) == {"chunk", "*"}
    assert handlers["chunk"].purge_targets == ["a", "b", "any"] and handlers["*"].purge_targets == ["any"]
    assert dict(reg).keys() == handlers.keys()  # Mapping view: usable as create_app(outbox_handlers=reg)


# ------------------------------------------------------------------------------ end to end
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


@pytest.fixture
def live():
    tokens = {"tok": {"tenant_id": "t1", "roles": ["ingest", "revoke", "read", "admin"], "subject": "x"}}
    app = create_app("sqlite://", tokens=tokens, outbox_interval=0)
    with TestClient(app) as tc:
        c = InvariantClient("http://testserver", "t1", auth_token="tok", transport=_Bridge(tc))
        yield app, c
        c.close()


def test_crash_between_revocation_and_purge_never_exposes_and_purge_is_idempotent(live):
    app, c = live
    backend, redis = InMemoryVectorBackend(), DictRedis()
    reg = PurgeRegistry()
    reg.register("chunk", VectorPurgeTarget(backend)).register("cache", CachePurgeTarget(redis))
    dispatcher = OutboxDispatcher(app.state.session_factory, reg.as_outbox_handlers())

    vs = GuardedVectorStore(c, U, "rag", backend)
    cache = GuardedCache(c, U, "rag", redis)
    source = new_source("t1", "kb/doc", "body", "kb", classification="confidential")
    c.register_source(source)
    other = new_source("t1", "kb/other", "other", "kb", classification="confidential")
    c.register_source(other)
    chunk = vs.add_derived([source], "secret chunk", [1.0, 0.0])
    keep = vs.add_derived([other], "kept chunk", [0.0, 1.0])
    cache.put("k", "cached secret", [chunk])
    cache.put("keep", "cached ok", [keep])
    assert len(backend._rows) == 2 and len(redis.data) == 4  # 2 entries + 2 index records

    c.submit_revocation({"source_id": source["context_id"], "reason": "deleted", "actor": "t"})
    # "Crash": the dispatcher never runs. Guarded reads are already denied; bytes are still physically there.
    allowed, blocked = vs.search([1.0, 0.0], k=5)
    assert [h.context_id for h in allowed] == [keep["context_id"]]
    assert [b.context_id for b in blocked] == [chunk["context_id"]]
    assert cache.get("k")[0] is None
    assert chunk["context_id"] in backend._rows  # not purged yet
    with app.state.session_factory() as s:
        assert outbox_stats(s)["totals"]["pending"] >= 3

    # Restarted dispatcher drains the outbox.
    res = dispatcher.run_once()
    assert res.failed == 0 and res.done >= 1
    assert chunk["context_id"] not in backend._rows and keep["context_id"] in backend._rows
    assert not any(chunk["context_id"] in k for k in redis.data)
    assert "keep" in redis.data  # unrelated lineage untouched
    with app.state.session_factory() as s:
        st = outbox_stats(s)
        # Only the source row remains: sources are purged by their own system, so no handler claims it.
        assert st["by_store_kind"]["source"] == {"pending": 1} and st["dead"] == 0
        assert st["by_store_kind"]["chunk"] == {"done": 1} and st["by_store_kind"]["cache"] == {"done": 1}

    # Re-run (and forced redelivery of the same rows) is a no-op, not an error.
    assert dispatcher.run_once().leased == 0
    for rw in (SimpleNamespace(tenant_id="t1", context_id=chunk["context_id"], version=chunk["object_version"], store_kind="chunk"),):
        reg.purge(rw)
    assert chunk["context_id"] not in backend._rows
    assert vs.search([1.0, 0.0], k=5)[0][0].context_id == keep["context_id"]


def test_failed_purge_retries_with_backoff_then_completes(live):
    app, c = live
    backend = InMemoryVectorBackend()

    class Flaky(VectorPurgeTarget):
        down = True

        def purge(self, rw):
            if self.down:
                raise ConnectionError("vector store unreachable")
            super().purge(rw)

    target = Flaky(backend)
    reg = PurgeRegistry().register("chunk", target)
    dispatcher = OutboxDispatcher(app.state.session_factory, reg.as_outbox_handlers())
    vs = GuardedVectorStore(c, U, "rag", backend)
    source = new_source("t1", "kb/d", "b", "kb")
    c.register_source(source)
    chunk = vs.add_derived([source], "chunk", [1.0, 0.0])
    c.submit_revocation({"source_id": source["context_id"], "reason": "deleted", "actor": "t"})

    now = datetime.now(UTC)
    r1 = dispatcher.run_once(now)
    assert r1.failed == 1 and chunk["context_id"] in backend._rows
    assert vs.search([1.0, 0.0])[0] == []  # still denied while purge is failing
    target.down = False
    assert dispatcher.run_once(now).leased == 0  # backoff not elapsed
    r2 = dispatcher.run_once(now + timedelta(seconds=10))
    assert r2.done == 1 and chunk["context_id"] not in backend._rows
