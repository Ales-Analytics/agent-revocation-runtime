import pytest
from ales_sdk import AlesHTTPError, FailMode, new_derivative, new_source

P = {"type": "user", "id": "alice"}


def _setup(client):
    src = new_source("t1", "doc", b"x", "kb")
    client.register_source(src)
    chunk = new_derivative("chunk", [src], "t1", "chunk", b"c")
    ref = client.register_derivation(chunk)
    assert ref["context_id"] == chunk["context_id"]
    return src, chunk


def test_request_shapes_and_flow(make_client, server):
    c = make_client(auth_token="tok")
    src, chunk = _setup(c)
    r = c.authorize(P, "rag", [chunk["context_id"]], agent_id="ag", session_id="s")
    assert r.decision == "ALLOW" and r.revocation_epoch == 0
    assert server.requests[-1][2]["agent_id"] == "ag"
    out = c.submit_revocation({"source_id": src["context_id"], "reason": "deleted"})
    assert out["revocation_epoch"] == 1 and "event_id" in out
    r2 = c.authorize(P, "rag", [chunk["context_id"]])
    assert r2.decision == "DENY" and r2.reason == ["ANCESTOR_ACL_REVOKED"]
    assert c.lineage(chunk["context_id"])["ancestors"] == []
    assert c.verify("langgraph", "strict")["passed"] is True
    assert server.requests[-1][2] == {"tenant_id": "t1", "adapter": "langgraph", "mode": "strict"}
    assert c._http.headers["authorization"] == "Bearer tok"


def test_http_error(make_client):
    c = make_client()
    with pytest.raises(AlesHTTPError) as e:
        c._request("GET", "/nope")
    assert e.value.status_code == 404


def test_allow_cached_then_invalidated_by_epoch(make_client, server):
    c = make_client()
    src, chunk = _setup(c)
    cid = chunk["context_id"]
    c.authorize(P, "rag", [cid])
    n = len(server.requests)
    r = c.authorize(P, "rag", [cid])
    assert r.from_cache and len(server.requests) == n  # served from cache, no server call
    c.submit_revocation({"source_id": src["context_id"], "reason": "deleted"})
    r = c.authorize(P, "rag", [cid])
    assert not r.from_cache and r.decision == "DENY"


def test_deny_never_cached(make_client, server):
    c = make_client()
    _, chunk = _setup(c)
    server.deny_all = True
    cid = chunk["context_id"]
    c.authorize(P, "rag", [cid])
    assert len(c.cache) == 0
    server.deny_all = False
    assert c.authorize(P, "rag", [cid]).decision == "ALLOW"  # not stuck on a cached deny


def test_unknown_object_not_cached(make_client):
    c = make_client()
    r = c.authorize(P, "rag", ["00000000-0000-4000-8000-000000000000"])
    assert r.decision == "UNKNOWN" and len(c.cache) == 0


def test_server_down_enforce_fails_closed(make_client, server):
    c = make_client(fail_mode=FailMode.ENFORCE)
    server.down = True
    r = c.authorize(P, "rag", ["x"])
    assert r.decision == "UNKNOWN" and r.offline and r.reason == ["POLICY_SNAPSHOT_STALE"]


def test_bounded_offline_lease(make_client, server, clock):
    c = make_client(fail_mode="BOUNDED_OFFLINE", offline_lease_seconds=60)
    c.cache.max_ttl = 1000
    _, chunk = _setup(c)
    cid = chunk["context_id"]
    assert c.authorize(P, "rag", [cid]).decision == "ALLOW"
    server.down = True
    clock.t += 20
    r = c.authorize(P, "rag", [cid])
    assert r.decision == "ALLOW" and r.from_cache
    clock.t += 100  # lease expired
    r = c.authorize(P, "rag", [cid])
    assert r.decision == "UNKNOWN" and r.lease_ok is False and r.offline
