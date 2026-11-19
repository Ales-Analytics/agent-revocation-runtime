"""Readiness, body cap, outbox worker, lineage correctness and the full SDK end-to-end flows."""

from __future__ import annotations

import threading
import time

import pytest
from ales_core import InvalidationOutbox
from ales_sdk import FailMode, InvariantClient, new_derivative, new_source
from ales_sdk.errors import AuthError, SnapshotError, TenantMismatchError
from ales_server import create_app
from ales_server.config import ConfigError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from server_helpers import (
    T1,
    T2,
    TOKENS,
    FakeClock,
    P,
    TestClientTransport,
    authorize_body,
    chain,
    pub_b64,
    sign_env,
)
from sqlalchemy import create_engine, select, text


def test_readyz_ok_after_migrations(client):
    r = client.get("/v1/readyz", headers={})
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "checks": {"database": "ok", "migrations": "ok"}}


def test_readyz_503_when_migrations_not_current(client):
    with client.app.state.engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = '0000_stale'"))
    r = client.get("/v1/readyz")
    assert r.status_code == 503 and r.json()["checks"]["migrations"] == "behind"
    assert client.get("/v1/healthz").status_code == 200  # liveness is independent of readiness


def test_readyz_503_when_schema_missing(client):
    with client.app.state.engine.begin() as conn:
        conn.execute(text("DROP TABLE alembic_version"))
    r = client.get("/v1/readyz")
    assert r.status_code == 503 and r.json()["checks"]["migrations"] == "behind"


def test_readyz_503_when_database_unreachable(client, tmp_path):
    client.app.state.engine = create_engine(f"sqlite:///{tmp_path / 'no' / 'such' / 'dir' / 'x.db'}")
    r = client.get("/v1/readyz")
    assert r.status_code == 503
    assert r.json()["checks"]["database"] == "unavailable"
    assert "sqlite" not in r.text.lower().replace('"unavailable"', "")  # no driver detail leaks


def test_startup_runs_migrations_on_a_file_database(tmp_path):
    url = f"sqlite:///{tmp_path / 'app.db'}"
    with TestClient(create_app(url, tokens=TOKENS, outbox_interval=0)) as c:
        assert c.get("/v1/readyz").status_code == 200
    with TestClient(create_app(url, tokens=TOKENS, outbox_interval=0)) as c:  # second start: idempotent
        assert c.get("/v1/readyz").status_code == 200


def test_body_cap_413(make_client):
    c = make_client(max_body=2000)
    big = {"x": "a" * 5000}
    r = c.post("/v1/revocations", json=big)
    assert r.status_code == 413 and "exceeds" in r.json()["detail"]
    small = chain()[0]
    assert len(str(small)) < 2000
    assert c.post("/v1/sources", json=small).status_code == 200


def test_body_cap_applies_before_authentication(make_client):
    c = make_client(max_body=500)
    r = TestClient(c.app).post(
        "/v1/sources", content=b"x" * 600, headers={"Content-Type": "application/json"}
    )
    assert r.status_code == 413


def test_body_cap_cannot_be_bypassed_with_chunked_encoding(make_client):
    c = make_client(max_body=1000)

    def gen():
        for _ in range(10):
            yield b"y" * 500

    r = c.post("/v1/sources", content=gen(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    # a chunked body under the cap still works
    ok = c.post(
        "/v1/authorize",
        content=iter(
            [
                b'{"tenant_id":"t1","principal":{"type":"user","id":"a"},',
                b'"purpose":"p","objects":[{"context_id":"x"}]}',
            ]
        ),
        headers={"Content-Type": "application/json"},
    )
    assert ok.status_code == 200


def test_body_cap_exact_boundary(make_client):
    body = b'{"source_id":"' + b"s" * 50 + b'","reason":"deleted"}'
    c = make_client(max_body=len(body))
    assert (
        c.post("/v1/revocations", content=body, headers={"Content-Type": "application/json"}).status_code
        != 413
    )
    c2 = make_client(max_body=len(body) - 1)
    assert (
        c2.post("/v1/revocations", content=body, headers={"Content-Type": "application/json"}).status_code
        == 413
    )


def test_default_body_cap_is_one_megabyte(client):
    assert client.app.state.settings.max_body == 1_048_576
    r = client.post(
        "/v1/revocations", content=b"z" * (1_048_576 + 1), headers={"Content-Type": "application/json"}
    )
    assert r.status_code == 413


def test_invalid_content_length_rejected(client):
    r = client.post(
        "/v1/revocations",
        content=b"{}",
        headers={"Content-Length": "abc", "Content-Type": "application/json"},
    )
    assert r.status_code in (400, 413)  # h11/httpx may reject first; never a 2xx


def test_body_cap_from_env_and_bad_values():
    c = TestClient(create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_MAX_BODY": "300"}))
    assert (
        c.post(
            "/v1/revocations", content=b"q" * 301, headers={**T1, "Content-Type": "application/json"}
        ).status_code
        == 413
    )
    for bad in ("0", "-1", "lots"):
        with pytest.raises(ConfigError):
            create_app("sqlite://", tokens=TOKENS, env={"ALES_MAX_BODY": bad})


def test_outbox_stats_shape(client):
    r = client.get("/v1/outbox/stats")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"totals", "by_store_kind", "dead", "worker"}
    assert set(body["totals"]) >= {"pending", "leased", "done", "dead"}
    assert body["dead"] == 0 and body["by_store_kind"] == {}
    assert body["worker"] == {"running": False, "interval_seconds": 0.0, "handlers": "log_only"}


def test_outbox_stats_count_pending_rows_per_tenant(client):
    src, chunk, _ = chain()
    client.post("/v1/sources", json=src)
    client.post("/v1/derivations", json=chunk)
    client.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"})
    stats = client.get("/v1/outbox/stats").json()
    assert stats["totals"]["pending"] == 2 and set(stats["by_store_kind"]) == {"source", "chunk"}
    assert client.get("/v1/outbox/stats", headers=T2).json()["totals"]["pending"] == 0


def test_worker_not_started_for_in_memory_sqlite(make_client):
    c = make_client(outbox_interval=0.05)
    assert c.app.state.outbox_worker is None
    assert c.get("/v1/outbox/stats").json()["worker"]["running"] is False


def test_outbox_worker_dispatches_and_stops_cleanly(tmp_path):
    seen: list[str] = []
    lock = threading.Lock()

    def handler(row: InvalidationOutbox) -> None:
        with lock:
            seen.append(f"{row.store_kind}:{row.context_id}")

    app = create_app(
        f"sqlite:///{tmp_path / 'w.db'}", tokens=TOKENS, outbox_interval=0.05, outbox_handlers={"*": handler}
    )
    with TestClient(app, headers=dict(T1)) as c:
        worker = app.state.outbox_worker
        assert worker.running
        src, chunk, _ = chain()
        c.post("/v1/sources", json=src)
        c.post("/v1/derivations", json=chunk)
        c.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"})
        deadline = time.time() + 10
        stats = c.get("/v1/outbox/stats").json()
        while stats["totals"]["done"] < 2 and time.time() < deadline:
            time.sleep(0.05)
            stats = c.get("/v1/outbox/stats").json()
        assert stats["totals"]["done"] == 2 and stats["totals"]["pending"] == 0
        assert stats["worker"] == {"running": True, "interval_seconds": 0.05, "handlers": "custom"}
        assert sorted(seen) == sorted([f"source:{src['context_id']}", f"chunk:{chunk['context_id']}"])
    assert not worker.running  # joined on shutdown


def test_outbox_worker_default_handler_is_log_only_and_labelled(tmp_path, caplog):
    app = create_app(f"sqlite:///{tmp_path / 'w2.db'}", tokens=TOKENS, outbox_interval=0.05)
    with caplog.at_level("INFO", logger="ales.server.outbox"), TestClient(app, headers=dict(T1)) as c:
        src = chain()[0]
        c.post("/v1/sources", json=src)
        c.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"})
        deadline = time.time() + 10
        while c.get("/v1/outbox/stats").json()["totals"]["done"] < 1 and time.time() < deadline:
            time.sleep(0.05)
        assert c.get("/v1/outbox/stats").json()["worker"]["handlers"] == "log_only"
    msgs = [r.getMessage() for r in caplog.records]
    assert any("LOG-ONLY" in m and src["context_id"] in m for m in msgs)
    assert not any("secret" in m for m in msgs)


def test_outbox_worker_survives_a_failing_handler(tmp_path):
    calls = []

    def flaky(row):
        calls.append(row.id)
        raise RuntimeError("store down")

    app = create_app(
        f"sqlite:///{tmp_path / 'w3.db'}", tokens=TOKENS, outbox_interval=0.05, outbox_handlers={"*": flaky}
    )
    with TestClient(app, headers=dict(T1)) as c:
        src = chain()[0]
        c.post("/v1/sources", json=src)
        c.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"})
        deadline = time.time() + 10
        while not calls and time.time() < deadline:
            time.sleep(0.05)
        assert calls and app.state.outbox_worker.running
        assert c.get("/v1/snapshot").status_code == 200  # request path unaffected
        stats = c.get("/v1/outbox/stats").json()
        assert stats["totals"]["done"] == 0  # failed purge is retried with backoff, not marked done


def test_worker_interval_validation():
    with pytest.raises(ConfigError):
        create_app("sqlite://", tokens=TOKENS, env={"ALES_OUTBOX_INTERVAL": "-1"})
    with pytest.raises(ConfigError):
        create_app("sqlite://", tokens=TOKENS, env={"ALES_OUTBOX_INTERVAL": "soon"})


def test_lineage_tombstoned_flag_is_time_correct(client):
    """A revocation that is accepted now but effective in the future must not report tombstoned yet."""
    src, chunk, summ = chain()
    for env, path in ((src, "/v1/sources"), (chunk, "/v1/derivations"), (summ, "/v1/derivations")):
        client.post(path, json=env)
    future = "2999-01-01T00:00:00Z"
    r = client.post(
        "/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted", "effective_at": future}
    )
    assert r.status_code == 200
    body = client.get(f"/v1/lineage/{chunk['context_id']}").json()
    assert [n["tombstoned"] for n in body["ancestors"]] == [False]
    assert [n["tombstoned"] for n in body["descendants"]] == [False]
    # and an immediately-effective revocation flips the flag for descendants too
    client.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "acl_changed"})
    body = client.get(f"/v1/lineage/{chunk['context_id']}").json()
    assert body["ancestors"][0]["tombstoned"] is True and body["descendants"][0]["tombstoned"] is True


def _sdk(client, tenant="t1", token="tok-t1-all", **kw):
    transport = TestClientTransport(client)
    return InvariantClient("http://testserver", tenant, token, transport=transport, **kw), transport


def test_sdk_auth_failures_surface_as_typed_errors(client):
    sdk, _ = _sdk(client, token="wrong-token")
    with pytest.raises(AuthError) as ei:
        sdk.authorize(P, "rag", ["x"])
    assert ei.value.status_code == 401
    sdk2, _ = _sdk(client, tenant="t2")  # t1's token claiming tenant t2
    with pytest.raises(TenantMismatchError):
        sdk2.authorize(P, "rag", ["x"])
    sdk3, _ = _sdk(client, token="tok-t1-read")
    with pytest.raises(AuthError) as ei:
        sdk3.register_source(new_source("t1", "d", b"x", "kb"))
    assert ei.value.status_code == 403 and not isinstance(ei.value, TenantMismatchError)


def test_sdk_bounded_offline_with_server_snapshot(make_client):
    """authorize online -> kill the transport -> cached ALLOW inside the lease -> deny after the lease."""
    c = make_client(snapshot_lease=60)
    pub = c.get("/v1/snapshot/public_key").json()["public_key_b64"]
    clock = FakeClock()
    sdk, transport = _sdk(
        c, fail_mode=FailMode.BOUNDED_OFFLINE, snapshot_public_key=pub, clock=clock, offline_lease_seconds=60
    )
    src = new_source("t1", "kb/doc.md", "secret text", "kb", classification="confidential")
    chunk = new_derivative("chunk", [src], "t1", "chunk", b"c")
    sdk.register_source(src)
    sdk.register_derivation(chunk)

    online = sdk.authorize(P, "rag", [chunk["context_id"]])
    assert online.allowed and not online.from_cache and not online.offline
    snap = sdk.snapshot
    assert snap is not None and snap.revocation_epoch == 0 and snap.lease_seconds == 60
    assert sdk.snapshot_valid()

    transport.down = True  # control plane unreachable
    clock.advance(10)
    offline = sdk.authorize(P, "rag", [chunk["context_id"]])
    assert offline.allowed and offline.from_cache  # served from the cache under a valid snapshot lease
    assert sdk.lease_ok()

    clock.advance(55)  # 65s since the snapshot was received: lease spent
    expired = sdk.authorize(P, "rag", [chunk["context_id"]])
    assert not expired.allowed and expired.decision == "UNKNOWN"
    assert expired.reason == ["POLICY_SNAPSHOT_STALE"] and expired.offline and not expired.lease_ok
    assert not sdk.lease_ok()

    transport.down = False  # recovery: a fresh signed snapshot restores service, and a revocation denies
    back = sdk.authorize(P, "rag", [chunk["context_id"]])
    assert back.allowed
    sdk.submit_revocation({"source_id": src["context_id"], "reason": "deleted"})
    after = sdk.authorize(P, "rag", [chunk["context_id"]])
    assert after.decision == "DENY"
    transport.down = True
    assert not sdk.authorize(P, "rag", [chunk["context_id"]]).allowed  # a DENY is never served from cache


def test_sdk_rejects_snapshot_signed_by_a_different_key(make_client):
    c = make_client()
    wrong = pub_b64(Ed25519PrivateKey.generate())
    sdk, _ = _sdk(c, fail_mode=FailMode.BOUNDED_OFFLINE, snapshot_public_key=wrong)
    with pytest.raises(SnapshotError) as ei:
        sdk.refresh_snapshot()
    assert ei.value.reason == "bad_signature" and not sdk.snapshot_valid()


def test_sdk_full_flow_with_signing_required(make_client):
    c = make_client(require_signatures=True)
    key = Ed25519PrivateKey.generate()
    assert c.post("/v1/admin/keys", json={"key_id": "k1", "public_key_b64": pub_b64(key)}).status_code == 201
    sdk, _ = _sdk(c)
    src, chunk, _ = chain()
    with pytest.raises(Exception) as ei:
        sdk.register_source(src)
    assert getattr(ei.value, "status_code", None) == 403
    assert sdk.register_source(sign_env(src, key, "k1"))["context_id"] == src["context_id"]
    assert sdk.register_derivation(sign_env(chunk, key, "k1"))["context_id"] == chunk["context_id"]
    assert sdk.authorize(P, "rag", [chunk["context_id"]]).allowed


def test_pending_outbox_rows_are_visible_to_ops(client):
    sdk, _ = _sdk(client)
    src = new_source("t1", "d", b"x", "kb")
    sdk.register_source(src)
    sdk.submit_revocation({"source_id": src["context_id"], "reason": "deleted"})
    with client.app.state.session_factory() as s:
        assert s.scalar(select(InvalidationOutbox.id)) is not None
    assert client.get("/v1/outbox/stats").json()["totals"]["pending"] == 1


def test_authorize_passes_valid_until_through(client):
    """A pending future-dated revocation surfaces as valid_until (response + per object); none otherwise."""
    src, chunk, summ = chain()
    for env, path in ((src, "/v1/sources"), (chunk, "/v1/derivations"), (summ, "/v1/derivations")):
        client.post(path, json=env)
    body = authorize_body("t1", summ["context_id"])
    first = client.post("/v1/authorize", json=body).json()
    assert first["decision"] == "ALLOW" and first["valid_until"] is None
    assert first["objects"][0]["valid_until"] is None

    r = client.post(
        "/v1/revocations",
        json={"source_id": src["context_id"], "reason": "deleted", "effective_at": "2999-01-01T00:00:00Z"},
    )
    assert r.status_code == 200
    pending = client.post("/v1/authorize", json=body).json()
    assert pending["decision"] == "ALLOW"  # not yet effective: decision semantics unchanged
    assert pending["valid_until"].startswith("2999-01-01T00:00:00") and pending["valid_until"].endswith("Z")
    assert pending["objects"][0]["valid_until"] == pending["valid_until"]
