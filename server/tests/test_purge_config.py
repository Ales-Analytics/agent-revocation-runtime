"""ALES_PURGE_TARGETS wiring: parsing, fail-closed startup, lazy build, verified purge, end-to-end via the outbox."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from ales_sdk import new_derivative
from ales_server import create_app
from ales_server.config import ConfigError
from ales_server.purge_config import PurgeVerificationError, VerifiedTarget, build_purge_wiring
from server_helpers import T1, TOKENS, chain

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "adapters"))
import ales_adapters as ad
from ales_adapters.purge import cache_index_key


@dataclass
class Row:
    tenant_id: str
    context_id: str
    version: str
    store_kind: str


def _env(*specs, **extra):
    return {"ALES_PURGE_TARGETS": json.dumps(list(specs)), **extra}


# --------------------------------------------------------------------------------------- parsing
def test_unset_means_no_wiring():
    assert build_purge_wiring({}) is None
    assert build_purge_wiring({"ALES_PURGE_TARGETS": "  "}) is None


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "{}",
        "[]",
        '["x"]',
        '[{"kind":"chunk","type":"s3","url":"x"}]',
        '[{"kind":"Chunk!","type":"redis","url":"redis://x"}]',
        '[{"type":"redis","url":"redis://x"}]',
        '[{"kind":"cache","type":"redis"}]',
        '[{"kind":"chunk","type":"qdrant","url":"http://x"}]',
        '[{"kind":"chunk","type":"pgvector","url":"postgresql://x","table":"t"}]',  # native needs dim
        '[{"kind":"chunk","type":"pgvector","url":"postgresql://x","table":"bad name","dim":3}]',
        '[{"kind":"chunk","type":"pgvector","url":"postgresql://x","table":"t","dim":3,"backend":"x"}]',
    ],
)
def test_malformed_specs_are_config_errors(raw):
    with pytest.raises(ConfigError):
        build_purge_wiring({"ALES_PURGE_TARGETS": raw})


def test_missing_adapters_package_is_config_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "ales_adapters", None)  # makes `import ales_adapters` raise ImportError
    with pytest.raises(ConfigError, match="ales_adapters"):
        build_purge_wiring(_env({"kind": "cache", "type": "redis", "url": "redis://x"}))


def test_missing_client_library_is_config_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "qdrant_client", None)
    with pytest.raises(ConfigError, match="qdrant_client"):
        build_purge_wiring(_env({"kind": "chunk", "type": "qdrant", "url": "http://x", "collection": "c"}))


def test_bad_config_fails_create_app():
    with pytest.raises(ConfigError):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_PURGE_TARGETS": "garbage"})


def test_unreachable_store_does_not_stop_startup_and_failure_is_not_cached(monkeypatch):
    """Targets connect lazily: a store that is down at boot does not block the control plane."""
    import redis

    calls = {"n": 0}
    shared = ad.DictRedis()

    def from_url(url, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("redis down")
        return shared

    monkeypatch.setattr(redis.Redis, "from_url", staticmethod(from_url))
    w = build_purge_wiring(_env({"kind": "cache", "type": "redis", "url": "redis://down:6379/0"}))
    assert w is not None and calls["n"] == 0
    row = Row("t1", "c1", "v1", "cache")
    with pytest.raises(ad.PurgeError):
        w.registry.purge(row)
    w.registry.purge(row)  # second attempt rebuilds and succeeds (nothing stored = success)
    assert calls["n"] == 2


# ------------------------------------------------------------------------------ redis / cache
class _StickyRedis(ad.DictRedis):
    """A redis whose DELETE of the data key silently does nothing (simulates a failed purge)."""

    def delete(self, *keys):
        return super().delete(*[k for k in keys if "__ales_idx__" in k])


def _put_cache(r, prefix, key, ctx, ver):
    r.set(prefix + key, json.dumps({"value": 1, "context_id": ctx, "version": ver}))
    r.set(cache_index_key(prefix, ctx), json.dumps({"key": key, "version": ver}))


def _patch_redis(monkeypatch, fake):
    import redis

    monkeypatch.setattr(redis.Redis, "from_url", staticmethod(lambda url, **kw: fake))


def test_cache_purge_verified_and_superseded_version_untouched(monkeypatch):
    fake = ad.DictRedis()
    _patch_redis(monkeypatch, fake)
    w = build_purge_wiring(_env({"kind": "cache", "type": "redis", "url": "redis://x", "prefix": "p:"}))
    assert w is not None and w.target_names() == ["redis"]
    _put_cache(fake, "p:", "k", "c1", "v1")
    row = Row("t1", "c1", "v1", "cache")
    assert w.verify_purge(row) is False  # still present before the purge
    w.registry.purge(row)
    assert fake.data == {} and w.verify_purge(row) is True
    # a purge for an OLD version leaves the newer entry alone and is not a verification failure
    _put_cache(fake, "p:", "k", "c1", "v2")
    w.registry.purge(Row("t1", "c1", "v1", "cache"))
    assert "p:k" in fake.data
    assert w.verify_purge(Row("t1", "c1", "v1", "cache")) is True


def test_cache_purge_verification_failure_raises(monkeypatch):
    fake = _StickyRedis()
    _patch_redis(monkeypatch, fake)
    w = build_purge_wiring(_env({"kind": "cache", "type": "redis", "url": "redis://x"}))
    assert w is not None
    _put_cache(fake, "", "k", "c1", "v1")
    with pytest.raises(ad.PurgeError, match="still present"):
        w.registry.purge(Row("t1", "c1", "v1", "cache"))
    with pytest.raises(PurgeVerificationError):
        w.targets[0].purge(Row("t1", "c1", "v1", "cache"))


# --------------------------------------------------------------------------------------- qdrant
def test_qdrant_purge_and_verify(monkeypatch):
    import qdrant_client

    mem = qdrant_client.QdrantClient(":memory:")
    monkeypatch.setattr(qdrant_client, "QdrantClient", lambda **kw: mem)
    w = build_purge_wiring(
        _env({"kind": ["chunk", "embedding"], "type": "qdrant", "url": "http://x", "collection": "col", "name": "q"})
    )
    assert w is not None
    be = ad.QdrantBackend(mem, collection="col", dim=2)
    be.add("c1", [1.0, 0.0], {"version": "v1"})
    be.add("c2", [0.0, 1.0], {"version": "v2"})
    assert w.verify_purge(Row("t1", "c1", "v1", "chunk")) is False
    w.registry.purge(Row("t1", "c1", "v1", "chunk"))
    assert not be.contains("c1") and w.verify_purge(Row("t1", "c1", "v1", "chunk")) is True
    # superseded-version purge: newer version stays, no verification failure
    w.registry.purge(Row("t1", "c2", "v1", "embedding"))
    assert be.contains("c2")
    assert w.kinds["chunk"] == w.kinds["embedding"]


def test_qdrant_missing_collection_is_success(monkeypatch):
    import qdrant_client

    mem = qdrant_client.QdrantClient(":memory:")
    monkeypatch.setattr(qdrant_client, "QdrantClient", lambda **kw: mem)
    w = build_purge_wiring(_env({"kind": "chunk", "type": "qdrant", "url": "http://x", "collection": "nope"}))
    assert w is not None
    w.registry.purge(Row("t1", "c1", "v1", "chunk"))


# -------------------------------------------------------------------------------------- pgvector
def test_pgvector_portable_purge_and_verify(tmp_path):
    from sqlalchemy import create_engine

    url = f"sqlite:///{tmp_path / 'vec.db'}"
    w = build_purge_wiring(
        _env({"kind": "chunk", "type": "pgvector", "backend": "portable", "url": url, "table": "vecs"})
    )
    assert w is not None
    be = ad.PgVectorBackend(create_engine(url), table="vecs")
    be.add("c1", [1.0, 0.0], {"version": "v1"})
    be.add("c2", [0.0, 1.0], {"version": "v2"})
    assert w.verify_purge(Row("t1", "c1", "v1", "chunk")) is False
    w.registry.purge(Row("t1", "c1", "v1", "chunk"))
    assert w.verify_purge(Row("t1", "c1", "v1", "chunk")) is True
    w.registry.purge(Row("t1", "c2", "v1", "chunk"))  # superseded: leaves v2
    assert w.verify_purge(Row("t1", "c2", "v2", "chunk")) is False


def test_target_that_never_removes_fails_verification():
    class Store:
        def __init__(self):
            self.purged = 0

    st = Store()

    def build():
        from ales_server.purge_config import _Store

        return _Store(lambda row: setattr(st, "purged", st.purged + 1), lambda row: True)

    t = VerifiedTarget("stubborn", build)
    with pytest.raises(PurgeVerificationError):
        t.purge(Row("t1", "c1", "v1", "chunk"))
    assert st.purged == 1 and t.verify_purge(Row("t1", "c1", "v1", "chunk")) is False


# ------------------------------------------------------------------------- end-to-end via the app
def _register_cache_chain(c):
    src, _, _ = chain()
    assert c.post("/v1/sources", json=src).status_code == 200
    env = new_derivative("cache", [src], "t1", "cache:k", b"payload")
    assert c.post("/v1/derivations", json=env).status_code == 200
    return src, env


def test_end_to_end_revocation_purges_redis_through_outbox(make_client, monkeypatch):
    fake = ad.DictRedis()
    _patch_redis(monkeypatch, fake)
    c = make_client(env=_env({"kind": "cache", "type": "redis", "url": "redis://x"}))
    stats = c.get("/v1/outbox/stats").json()
    assert stats["worker"]["handlers"] == "purge:redis"
    src, env = _register_cache_chain(c)
    _put_cache(fake, "", "k", env["context_id"], env["object_version"])
    assert c.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"}).status_code == 200
    out = c.post("/v1/outbox/run", headers={"Authorization": "Bearer tok-t1-admin"}).json()
    assert out["done"] >= 1 and out["failed"] == 0
    assert fake.data == {}


def test_end_to_end_verification_failure_leaves_row_for_retry(make_client, monkeypatch):
    fake = _StickyRedis()
    _patch_redis(monkeypatch, fake)
    c = make_client(env=_env({"kind": "cache", "type": "redis", "url": "redis://x"}))
    src, env = _register_cache_chain(c)
    _put_cache(fake, "", "k", env["context_id"], env["object_version"])
    c.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"})
    out = c.post("/v1/outbox/run", headers={"Authorization": "Bearer tok-t1-admin"}).json()
    assert out["failed"] == 1 and out["done"] == 0
    from ales_core import InvalidationOutbox
    from sqlalchemy import select

    with c.app.state.session_factory() as s:
        row = s.scalars(select(InvalidationOutbox).where(InvalidationOutbox.store_kind == "cache")).one()
    assert row.state == "pending" and "still present" in (row.last_error or "")


def test_explicit_outbox_handlers_take_precedence(make_client, monkeypatch):
    c = make_client(env=_env({"kind": "cache", "type": "redis", "url": "redis://x"}), outbox_handlers={"*": lambda r: None})
    assert c.get("/v1/outbox/stats", headers=T1).json()["worker"]["handlers"] == "custom"
