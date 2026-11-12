"""Guarded lifecycle against LIVE stores: Qdrant, PostgreSQL+pgvector, Redis.

Each test skips (with the reason) when its store is not reachable, so CI without the containers stays
green. Every run uses a unique collection / table / key prefix and removes it on teardown.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import httpx
import pytest
from ales_adapters import (
    CachePurgeTarget,
    GuardedCache,
    GuardedVectorStore,
    PgVectorNativeBackend,
    PurgeRegistry,
    QdrantBackend,
    VectorPurgeTarget,
)
from ales_adapters.live_stores import is_available, pg_engine, qdrant_client, redis_client, unavailable_reason
from ales_core import OutboxDispatcher, outbox_stats
from ales_sdk import InvariantClient, new_source
from ales_server import create_app
from fastapi.testclient import TestClient

U = {"type": "user", "id": "alice"}


def requires(store: str) -> pytest.MarkDecorator:
    return pytest.mark.skipif(not is_available(store), reason=unavailable_reason(store) or "")


# ------------------------------------------------------------------------------ control plane
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
def plane():
    tokens = {"tok": {"tenant_id": "t1", "roles": ["ingest", "revoke", "read", "admin"], "subject": "x"}}
    app = create_app("sqlite://", tokens=tokens, outbox_interval=0)
    with TestClient(app) as tc:
        c = InvariantClient("http://testserver", "t1", auth_token="tok", transport=_Bridge(tc))
        yield app, c
        c.close()


def _row(kind: str, cid: str, version: str) -> SimpleNamespace:
    return SimpleNamespace(tenant_id="t1", context_id=cid, version=version, store_kind=kind)


def _uid() -> str:
    return "ales_t_" + uuid.uuid4().hex[:12]


# ------------------------------------------------------------------------------ vector stores
class VectorRig:
    def __init__(self, backend, count, contains, drop):
        self.backend, self.count, self.contains, self.drop = backend, count, contains, drop


@pytest.fixture(params=["qdrant", "pgvector"])
def vector_rig(request):
    store = request.param
    if not is_available(store):
        pytest.skip(unavailable_reason(store))
    name = _uid()
    if store == "qdrant":
        b = QdrantBackend(qdrant_client(), name, dim=2)
    else:
        b = PgVectorNativeBackend(pg_engine(), name, dim=2)
    rig = VectorRig(b, b.count, b.contains, b.drop)
    yield rig
    rig.drop()


def test_native_cosine_ranking_and_payload_roundtrip(vector_rig):
    b = vector_rig.backend
    b.add("near", [1.0, 0.1], {"context_id": "near", "version": "1", "text": "n"})
    b.add("far", [0.0, 1.0], {"context_id": "far", "version": "1", "text": "f"})
    b.add("opp", [-1.0, 0.0], {"context_id": "opp", "version": "1"})
    hits = b.search([1.0, 0.0], 3)
    assert [h[0] for h in hits] == ["near", "far", "opp"]
    assert hits[0][1] == pytest.approx(0.995, abs=1e-2) and hits[2][1] == pytest.approx(-1.0, abs=1e-3)
    assert hits[0][2]["text"] == "n" and "_ales_id" not in hits[0][2]
    assert len(b.search([1.0, 0.0], 2)) == 2
    b.add("near", [0.0, 1.0], {"context_id": "near", "version": "2"})  # upsert replaces, no duplicate
    assert vector_rig.count() == 3 and b.search([0.0, 1.0], 1)[0][2]["version"] in ("1", "2")


def test_delete_is_idempotent_and_version_aware(vector_rig):
    b = vector_rig.backend
    b.add("c1", [1.0, 0.0], {"context_id": "c1", "version": "2"})
    b.add("c2", [0.0, 1.0], {"context_id": "c2", "version": "1"})
    b.add("c3", [1.0, 1.0], {"context_id": "c3"})  # no version in payload
    b.delete("missing")  # never stored: success
    b.delete("c1", version="1")  # stale purge must not remove the newer version
    assert vector_rig.contains("c1") and vector_rig.count() == 3
    b.delete("c3", version="9")  # payload carries no version: versioned delete still removes it
    assert not vector_rig.contains("c3")
    b.delete("c1", version="2")
    b.delete("c1", version="2")  # second delete: still success
    assert not vector_rig.contains("c1") and vector_rig.contains("c2")
    b.delete("c2")  # unversioned delete always removes
    assert vector_rig.count() == 0
    assert b.search([1.0, 0.0], 5) == []


def test_guarded_vector_lifecycle_with_physical_purge(vector_rig, plane):
    app, c = plane
    backend = vector_rig.backend
    reg = PurgeRegistry().register("chunk", VectorPurgeTarget(backend))
    dispatcher = OutboxDispatcher(app.state.session_factory, reg.as_outbox_handlers())
    vs = GuardedVectorStore(c, U, "rag", backend)

    source = new_source("t1", "kb/doc", "body", "kb", classification="confidential")
    other = new_source("t1", "kb/other", "other", "kb", classification="confidential")
    c.register_source(source)
    c.register_source(other)
    chunk = vs.add_derived([source], "secret chunk", [1.0, 0.0])
    keep = vs.add_derived([other], "kept chunk", [0.0, 1.0])
    assert vector_rig.count() == 2

    allowed, blocked = vs.search([1.0, 0.0], k=5)  # ALLOW before revocation
    assert {h.context_id for h in allowed} == {chunk["context_id"], keep["context_id"]} and not blocked
    assert next(h for h in allowed if h.context_id == chunk["context_id"]).payload["text"] == "secret chunk"

    c.submit_revocation({"source_id": source["context_id"], "reason": "deleted", "actor": "t"})
    allowed, blocked = vs.search([1.0, 0.0], k=5)  # blocked with a reason, before any purge ran
    assert [h.context_id for h in allowed] == [keep["context_id"]]
    assert [b.context_id for b in blocked] == [chunk["context_id"]]
    assert "ANCESTOR_DELETED" in blocked[0].reasons or "ANCESTOR_ACL_REVOKED" in blocked[0].reasons
    assert vector_rig.contains(chunk["context_id"])  # bytes still physically there

    res = dispatcher.run_once()  # physical purge through the real outbox
    assert res.failed == 0 and res.done >= 1
    assert not vector_rig.contains(chunk["context_id"]) and vector_rig.contains(keep["context_id"])
    assert vector_rig.count() == 1
    with app.state.session_factory() as s:
        assert outbox_stats(s)["by_store_kind"]["chunk"] == {"done": 1}

    assert dispatcher.run_once().leased == 0
    reg.purge(_row("chunk", chunk["context_id"], chunk["object_version"]))  # forced redelivery: no-op
    assert vector_rig.count() == 1
    assert [h.context_id for h in vs.search([1.0, 0.0], k=5)[0]] == [keep["context_id"]]


def test_purge_target_does_not_touch_newer_version(vector_rig):
    b = vector_rig.backend
    target = VectorPurgeTarget(b)
    b.add("ctx", [1.0, 0.0], {"context_id": "ctx", "version": "v2"})  # re-stored under the same context_id
    target.purge(_row("chunk", "ctx", "v1"))  # purge for the superseded version
    assert vector_rig.contains("ctx")
    target.purge(_row("chunk", "ctx", "v2"))
    assert not vector_rig.contains("ctx")


# ------------------------------------------------------------------------------ redis
@pytest.fixture(params=["str", "bytes"])
def redis_rig(request):
    if not is_available("redis"):
        pytest.skip(unavailable_reason("redis"))
    import redis
    from ales_adapters.live_stores import REDIS_URL

    r = redis_client() if request.param == "str" else redis.Redis.from_url(REDIS_URL, decode_responses=False)
    prefix = f"{_uid()}:"
    yield r, prefix
    keys = list(r.scan_iter(match=f"{prefix}*"))
    if keys:
        r.delete(*keys)


def _keys(r, prefix):
    return {k.decode() if isinstance(k, bytes) else k for k in r.scan_iter(match=f"{prefix}*")}


def test_guarded_cache_lifecycle_with_physical_purge(redis_rig, plane):
    r, prefix = redis_rig
    app, c = plane
    reg = PurgeRegistry().register("cache", CachePurgeTarget(r, prefix=prefix))
    dispatcher = OutboxDispatcher(app.state.session_factory, reg.as_outbox_handlers())
    cache = GuardedCache(c, U, "rag", r, prefix=prefix)

    source = new_source("t1", "kb/doc", "body", "kb", classification="confidential")
    other = new_source("t1", "kb/other", "other", "kb", classification="confidential")
    c.register_source(source)
    c.register_source(other)
    env = cache.put("k", {"answer": "secret"}, [source])
    cache.put("keep", {"answer": "ok"}, [other])
    assert len(_keys(r, prefix)) == 4  # 2 entries + 2 reverse-index records

    assert cache.get("k") == ({"answer": "secret"}, [])  # ALLOW
    c.submit_revocation({"source_id": source["context_id"], "reason": "deleted", "actor": "t"})

    # Isolate the purge path: re-plant the entry that guarded get() would have best-effort deleted.
    raw_before = r.get(prefix + "k")
    value, blocked = cache.get("k")
    assert value is None and blocked and blocked[0].decision == "DENY"
    assert "ANCESTOR_DELETED" in blocked[0].reasons or "ANCESTOR_ACL_REVOKED" in blocked[0].reasons
    r.set(prefix + "k", raw_before)  # simulate a replica / missed best-effort cleanup
    assert cache.get("k")[0] is None  # still denied by tombstone even though the bytes are present
    r.set(prefix + "k", raw_before)

    res = dispatcher.run_once()
    assert res.failed == 0 and res.done >= 1
    remaining = _keys(r, prefix)
    assert prefix + "k" not in remaining and f"{prefix}__ales_idx__{env['context_id']}" not in remaining
    assert prefix + "keep" in remaining and len(remaining) == 2

    assert dispatcher.run_once().leased == 0
    reg.purge(_row("cache", env["context_id"], env["object_version"]))  # idempotent re-purge
    assert len(_keys(r, prefix)) == 2
    assert cache.get("keep") == ({"answer": "ok"}, [])


def test_cache_purge_skips_newer_version_on_live_redis(redis_rig, plane):
    r, prefix = redis_rig
    _, c = plane
    source = new_source("t1", "kb/doc", "body", "kb")
    c.register_source(source)
    env = GuardedCache(c, U, "rag", r, prefix=prefix).put("k", 1, [source])
    target = CachePurgeTarget(r, prefix=prefix)
    target.purge(_row("cache", env["context_id"], "some-older-version"))
    assert prefix + "k" in _keys(r, prefix)  # newer version untouched
    idx = json.loads(r.get(f"{prefix}__ales_idx__{env['context_id']}"))
    assert idx["version"] == env["object_version"]
    target.purge(_row("cache", env["context_id"], env["object_version"]))
    assert _keys(r, prefix) == set()
    target.purge(_row("cache", env["context_id"], env["object_version"]))  # idempotent
    target.purge(_row("cache", "never-cached", "1"))


@requires("redis")
def test_live_redis_get_miss_is_plain_miss(plane):
    _, c = plane
    r = redis_client()
    assert GuardedCache(c, U, "rag", r, prefix=f"{_uid()}:").get("absent") == (None, [])
