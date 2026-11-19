import json
import threading
from datetime import UTC, datetime, timedelta

import pytest
from ales_sdk import (
    AlesConnectionError,
    AlesHTTPError,
    AuthError,
    ConfigError,
    DecisionCache,
    FailMode,
    InvariantClient,
    RequestTooLargeError,
    ServerUnavailableError,
    SessionResetRequired,
    SnapshotError,
    TenantMismatchError,
    canonical_bytes,
    enforce,
    guard_retrieval,
    make_key,
    new_derivative,
    new_source,
)
from sdk_fixtures import DEFAULT_TOKEN

P = {"type": "user", "id": "alice"}


def _chunk(c, name="a"):
    src = new_source("t1", name, name.encode(), "kb")
    c.register_source(src)
    ch = new_derivative("chunk", [src], "t1", name + "#0", b"c")
    c.register_derivation(ch)
    return src, ch["context_id"]


def _bounded(make_client, **kw):
    kw.setdefault("offline_lease_seconds", 60)
    return make_client(fail_mode="BOUNDED_OFFLINE", **kw)


def test_cache_key_has_eight_components_and_isolates():
    base = ("t1", "user", "alice", "rag", "c1", "v1", "p1", "agent-a")
    assert make_key(*base) == base
    cache = DecisionCache()
    assert cache.put(make_key(*base), "ALLOW", 1)
    for i, alt in [
        (0, "t2"),
        (1, "service"),
        (2, "bob"),
        (3, "other"),
        (4, "c2"),
        (5, "v2"),
        (6, "p2"),
        (7, "agent-b"),
    ]:
        probe = list(base)
        probe[i] = alt
        assert cache.get(make_key(*probe)) is None, f"component {i} not part of key"
    assert cache.get(make_key(*base)) == 1


def test_clients_sharing_a_cache_never_cross_tenants_or_principal_types(server, clock):
    cache = DecisionCache(clock=clock)

    def mk(tenant):
        return InvariantClient(
            "http://ales.test", tenant, auth_token="x", transport=server.transport(), cache=cache, clock=clock
        )

    a, b = mk("t1"), mk("t2")
    _, cid = _chunk(a)
    assert a.authorize({"type": "user", "id": "u"}, "rag", [cid]).decision == "ALLOW"
    n = len(server.requests)
    # same ids, other principal type: must go to the server, not the cache
    r = a.authorize({"type": "service", "id": "u"}, "rag", [cid])
    assert not r.from_cache and len(server.requests) == n + 1
    # same ids, other tenant: must go to the server
    r = b.authorize({"type": "user", "id": "u"}, "rag", [cid])
    assert not r.from_cache and server.requests[-1][2]["tenant_id"] == "t2"


def test_cache_thread_safety():
    cache = DecisionCache()
    errors = []

    def work(n):
        try:
            for i in range(500):
                k = make_key("t", "user", f"u{n}", "p", f"c{i}", None, "pv")
                cache.put(k, "ALLOW", 0)
                cache.get(k)
                len(cache)
                if i % 50 == 0:
                    cache.invalidate_context(f"c{i}")
        except Exception as e:  # noqa: BLE001  # pragma: no cover
            errors.append(e)

    ts = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors


def test_every_request_carries_bearer_and_tenant(make_client, server):
    c = make_client()
    _, cid = _chunk(c)
    c.authorize(P, "rag", [cid])
    c.lineage(cid)
    c.healthz()
    assert server.headers_log
    for h in server.headers_log:
        assert h["authorization"] == f"Bearer {DEFAULT_TOKEN}"
        assert h["x-tenant-id"] == "t1"


def test_token_mandatory_unless_anonymous(server):
    with pytest.raises(ConfigError):
        InvariantClient("http://ales.test", "t1", transport=server.transport())
    with pytest.raises(ConfigError):
        InvariantClient("http://ales.test", "t1", auth_token="   ", allow_anonymous=True)
    with pytest.raises(ConfigError):
        InvariantClient("http://ales.test", "t1", auth_token="bad\ntoken")
    c = InvariantClient("http://ales.test", "t1", allow_anonymous=True, transport=server.transport())
    c.healthz()
    assert "authorization" not in server.headers_log[-1]


def test_token_not_in_repr(make_client):
    assert DEFAULT_TOKEN not in repr(make_client())


def test_401_raises_auth_error_with_detail(make_client, server):
    server.strict_auth = True
    c = make_client(auth_token="wrong")
    with pytest.raises(AuthError) as e:
        c.authorize(P, "rag", ["x"])
    assert e.value.status_code == 401
    assert "invalid or missing bearer token" in str(e.value) and e.value.detail
    assert isinstance(e.value, AlesHTTPError)
    assert len([r for r in server.requests if r[1] == "/v1/authorize"]) == 1  # never retried


def test_403_tenant_mismatch_is_fatal_config_error(make_client, server):
    server.strict_auth = True
    server.tokens = {DEFAULT_TOKEN: "other-tenant"}
    c = make_client()
    with pytest.raises(TenantMismatchError) as e:
        c.authorize(P, "rag", ["x"])
    assert "t1" in str(e.value) and "token" in str(e.value)
    assert isinstance(e.value, AuthError)


def test_strict_server_accepts_valid_token(make_client, server):
    server.strict_auth = True
    c = make_client()
    _, cid = _chunk(c)
    assert c.authorize(P, "rag", [cid]).allowed


def test_bounded_offline_requires_snapshot_key(server):
    with pytest.raises(ConfigError):
        InvariantClient("http://ales.test", "t1", auth_token="t", fail_mode="BOUNDED_OFFLINE")
    with pytest.raises(ConfigError):
        InvariantClient(
            "http://ales.test", "t1", auth_token="t", fail_mode="BOUNDED_OFFLINE", snapshot_public_key="AAAA"
        )


def test_snapshot_verified_and_offline_allowed(make_client, server, clock):
    c = _bounded(make_client)
    _, cid = _chunk(c)
    assert c.authorize(P, "rag", [cid]).decision == "ALLOW"
    snap = c.snapshot
    assert snap is not None and snap.revocation_epoch == 0 and snap.policy_version == "p1"
    server.down = True
    clock.t += 20
    r = c.authorize(P, "rag", [cid])
    assert r.allowed and r.from_cache
    # a different (uncached) object offline: fail closed
    r = c.authorize(P, "rag", ["other-id"])
    assert r.decision == "UNKNOWN" and r.reason == ["POLICY_SNAPSHOT_STALE"] and r.offline


def test_snapshot_bad_signature_fails_closed(make_client, server, clock):
    server.corrupt_snapshot_signature = True
    c = _bounded(make_client)
    _, cid = _chunk(c)
    assert c.authorize(P, "rag", [cid]).decision == "ALLOW"  # online decisions still come from server
    assert c.snapshot is None
    assert c.last_snapshot_error is not None and c.last_snapshot_error.reason == "bad_signature"
    with pytest.raises(SnapshotError) as e:
        c.refresh_snapshot()
    assert e.value.reason == "bad_signature"
    server.down = True
    r = c.authorize(P, "rag", [cid])
    assert r.decision == "UNKNOWN" and r.reason == ["POLICY_SNAPSHOT_STALE"] and r.lease_ok is False


def test_snapshot_tampered_content_rejected(make_client, server):
    server.snapshot_extra = {"revocation_epoch": 99}  # altered after signing
    c = _bounded(make_client)
    with pytest.raises(SnapshotError) as e:
        c.refresh_snapshot()
    assert e.value.reason == "bad_signature"


def test_snapshot_wrong_key_rejected(make_client, server):
    from sdk_fixtures import FakeServer

    other = FakeServer()
    c = make_client(fail_mode="BOUNDED_OFFLINE", snapshot_public_key=other.public_key_b64)
    with pytest.raises(SnapshotError) as e:
        c.refresh_snapshot()
    assert e.value.reason == "bad_signature"


def test_snapshot_expired_lease_denies_offline(make_client, server, clock):
    server.lease_seconds = 10
    c = _bounded(make_client, offline_lease_seconds=3600)
    _, cid = _chunk(c)
    assert c.authorize(P, "rag", [cid]).allowed
    server.down = True
    clock.t += 5
    assert c.authorize(P, "rag", [cid]).allowed
    clock.t += 6  # 11s > 10s lease
    r = c.authorize(P, "rag", [cid])
    assert r.decision == "UNKNOWN" and r.reason == ["POLICY_SNAPSHOT_STALE"] and r.lease_ok is False


def test_snapshot_replayed_old_snapshot_rejected(make_client, server):
    old = datetime.now(UTC) - timedelta(hours=1)
    server.snapshot_issued_at = old.isoformat().replace("+00:00", "Z")
    c = _bounded(make_client)
    with pytest.raises(SnapshotError) as e:
        c.refresh_snapshot()
    assert e.value.reason == "expired"


def test_snapshot_epoch_mismatch_denies_offline(make_client, server, clock):
    c = _bounded(make_client)
    _, cid = _chunk(c)
    other, _ = _chunk(c, "b")
    c.submit_revocation({"source_id": other["context_id"], "reason": "deleted"})  # epoch -> 1
    server.snapshot_epoch = 0  # server hands out a snapshot older than the decision
    assert c.authorize(P, "rag", [cid]).allowed  # cached at epoch 1
    assert c.snapshot.revocation_epoch == 0
    server.down = True
    r = c.authorize(P, "rag", [cid])
    assert r.decision == "UNKNOWN" and r.reason == ["POLICY_SNAPSHOT_STALE"]


def test_snapshot_epoch_rollback_rejected(make_client, server):
    c = _bounded(make_client)
    src, _ = _chunk(c)
    c.submit_revocation({"source_id": src["context_id"], "reason": "deleted"})
    assert c.refresh_snapshot().revocation_epoch == 1
    server.snapshot_epoch = 0
    with pytest.raises(SnapshotError) as e:
        c.refresh_snapshot()
    assert e.value.reason == "epoch_regression"
    assert c.snapshot is None


def test_snapshot_tenant_mismatch_rejected(make_client, server):
    server.snapshot_tenant = "t2"
    c = _bounded(make_client)
    with pytest.raises(SnapshotError) as e:
        c.refresh_snapshot()
    assert e.value.reason == "tenant_mismatch"


def test_snapshot_bad_format_rejected(make_client, server):
    server.lease_seconds = 0
    c = _bounded(make_client)
    with pytest.raises(SnapshotError) as e:
        c.refresh_snapshot()
    assert e.value.reason == "bad_format"


def test_snapshot_refreshed_after_half_lease(make_client, server, clock):
    c = _bounded(make_client, offline_lease_seconds=60)
    _, cid = _chunk(c)
    c.authorize(P, "rag", [cid])
    first = c.snapshot
    n = len([r for r in server.requests if r[1] == "/v1/snapshot"])
    clock.t += 10
    c.authorize(P, "rag", [cid])
    assert len([r for r in server.requests if r[1] == "/v1/snapshot"]) == n
    clock.t += 25  # 35 >= 30 (half of 60)
    c.authorize(P, "rag", [cid])
    assert len([r for r in server.requests if r[1] == "/v1/snapshot"]) == n + 1
    assert c.snapshot.received_at > first.received_at


def test_revocation_while_online_not_served_from_cache_under_bounded(make_client, server, clock):
    c = _bounded(make_client)
    src, cid = _chunk(c)
    assert c.authorize(P, "rag", [cid]).allowed
    c.submit_revocation({"source_id": src["context_id"], "reason": "deleted"})
    assert c.authorize(P, "rag", [cid]).decision == "DENY"


def test_canonical_bytes_contract():
    payload = {
        "tenant_id": "t1",
        "revocation_epoch": 7,
        "policy_version": "p1",
        "issued_at": "2026-01-01T00:00:00Z",
        "lease_seconds": 300,
        "signature": "ignored",
        "key_id": "ignored",
    }
    assert canonical_bytes(payload) == (
        b'{"issued_at":"2026-01-01T00:00:00Z","lease_seconds":300,"policy_version":"p1",'
        b'"revocation_epoch":7,"tenant_id":"t1"}'
    )
    assert canonical_bytes({"tenant_id": "té"}) == '{"tenant_id":"té"}'.encode()
    with pytest.raises(SnapshotError):
        canonical_bytes({"lease_seconds": 1.5})


def test_get_retried_with_jitter(make_client, server):
    c = make_client()
    server.fail_next("/v1/healthz", 1)
    assert c.healthz() == {"status": "ok"}
    sleeps = make_client.sleeps
    assert len(sleeps) == 1 and 0 <= sleeps[0] <= c.retry_backoff


def test_authorize_retried_on_transport_failure_and_503(make_client, server):
    c = make_client()
    _, cid = _chunk(c)
    server.fail_next("/v1/authorize", 1)
    assert c.authorize(P, "rag", [cid]).allowed
    c2 = make_client()
    server.fail_next("/v1/authorize", 2, status=503)
    assert c2.authorize(P, "rag", [cid]).allowed


def test_retries_exhausted_authorize_fails_closed(make_client, server):
    c = make_client(max_retries=2)
    _, cid = _chunk(c)
    server.fail_next("/v1/authorize", 10, status=503)
    r = c.authorize(P, "rag", [cid])
    assert r.decision == "UNKNOWN" and r.offline
    assert len(make_client.sleeps) == 2
    assert make_client.sleeps[1] <= c.retry_backoff * 2


def test_retries_configurable_to_zero(make_client, server):
    c = make_client(max_retries=0)
    server.fail_next("/v1/healthz", 1)
    with pytest.raises(AlesConnectionError):
        c.healthz()
    assert make_client.sleeps == []


def test_non_idempotent_posts_not_retried(make_client, server):
    c = make_client()
    server.fail_next("/v1/sources", 1)
    with pytest.raises(AlesConnectionError):
        c.register_source(new_source("t1", "a", b"a", "kb"))
    server.fail_next("/v1/revocations", 1, status=503)
    with pytest.raises(ServerUnavailableError):
        c.submit_revocation({"source_id": "x", "reason": "r"})
    assert make_client.sleeps == []


def test_oversize_request_refused_client_side(make_client, server):
    c = make_client()
    n = len(server.requests)
    with pytest.raises(RequestTooLargeError) as e:
        c.authorize(P, "rag", ["x" * 2_000_000])
    assert e.value.size > e.value.limit
    assert len(server.requests) == n


def test_empty_objects_and_bad_principal_refused(make_client):
    from ales_sdk import InvalidRequestError

    c = make_client()
    with pytest.raises(InvalidRequestError):
        c.authorize(P, "rag", [])
    with pytest.raises(InvalidRequestError):
        c.authorize({"type": "user"}, "rag", ["x"])


def test_default_timeouts(make_client):
    t = make_client()._http.timeout
    assert t.connect == 3.0 and t.read == 10.0


def test_policy_version_change_drops_cache(make_client, server):
    c = make_client()
    _, cid = _chunk(c)
    c.authorize(P, "rag", [cid])
    assert len(c.cache) == 1
    server.policy_version = "p2"
    c.authorize(P, "other-purpose", [cid])
    keys = list(c.cache._entries)
    assert keys and all(k[6] == "p2" for k in keys)


def test_enforce_flags_reset_after_revocation_single_batch(make_client, server):
    c = make_client()
    s1, id1 = _chunk(c, "a")
    _, id2 = _chunk(c, "b")
    hits = [id1, id2]
    allowed, _ = guard_retrieval(c, P, "rag", hits, lambda h: h, session_id="s")
    assert allowed == hits
    v = enforce("s", c)
    assert not v.reset_required and v.revoked == [] and v.checked == 2
    c.submit_revocation({"source_id": s1["context_id"], "reason": "deleted"})
    n = len([r for r in server.requests if r[1] == "/v1/authorize"])
    v = enforce("s", c)
    assert v.reset_required
    assert [o.context_id for o in v.revoked] == [id1] and v.revoked[0].decision == "DENY"
    assert len([r for r in server.requests if r[1] == "/v1/authorize"]) == n + 1  # one batch call
    assert server.requests[-1][2]["session_id"] == "s"
    assert len(server.requests[-1][2]["objects"]) == 2


def test_enforce_empty_session_and_offline_fail_closed(make_client, server):
    c = make_client()
    assert not enforce("never-seen", c).reset_required
    _, cid = _chunk(c)
    guard_retrieval(c, P, "rag", [cid], lambda h: h, session_id="s")
    server.down = True
    c.cache.clear()
    assert enforce("s", c).reset_required  # cannot re-verify -> reset


def test_enforce_unverifiable_legacy_records_force_reset(make_client):
    c = make_client()
    c.session_taint.record("s", ["legacy-id"])
    v = enforce("s", c)
    assert v.reset_required and v.unverifiable == ["legacy-id"]
    _, cid = _chunk(c)
    c.session_taint.clear("s")
    c.session_taint.record("s", [cid])
    assert not enforce("s", c, principal=P, purpose="rag").reset_required


def test_guard_taint_check_pre_raises_on_tainted_session(make_client):
    c = make_client()
    s1, id1 = _chunk(c, "a")
    _, id2 = _chunk(c, "b")
    guard_retrieval(c, P, "rag", [id1], lambda h: h, session_id="s", taint_check="pre")
    c.submit_revocation({"source_id": s1["context_id"], "reason": "deleted"})
    with pytest.raises(SessionResetRequired) as e:
        guard_retrieval(c, P, "rag", [id2], lambda h: h, session_id="s", taint_check="pre")
    assert e.value.verdict.revoked[0].context_id == id1
    # default ("off") keeps the old behaviour
    allowed, _ = guard_retrieval(c, P, "rag", [id2], lambda h: h, session_id="s")
    assert allowed == [id2]
    c.session_taint.clear("s")
    allowed, _ = guard_retrieval(c, P, "rag", [id2], lambda h: h, session_id="s", taint_check="pre")
    assert allowed == [id2]


def test_guard_taint_check_validation(make_client):
    c = make_client()
    with pytest.raises(ConfigError):
        guard_retrieval(c, P, "rag", ["x"], lambda h: h, taint_check="pre")  # no session
    with pytest.raises(ConfigError):
        guard_retrieval(c, P, "rag", ["x"], lambda h: h, session_id="s", taint_check="always")


def test_failmode_enum_still_accepts_strings(make_client):
    assert make_client(fail_mode="ENFORCE").fail_mode is FailMode.ENFORCE
    with pytest.raises(ConfigError):
        make_client(fail_mode="NOPE")


def test_request_body_is_compact_json(make_client, server):
    c = make_client()
    c.authorize(P, "rag", ["x"])
    assert json.loads(json.dumps(server.requests[-1][2]))["tenant_id"] == "t1"


class _Wall:
    def __init__(self):
        import time

        self.t = time.time()

    def __call__(self):
        return self.t


def _iso(ts: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def test_cached_allow_not_served_past_valid_until(make_client, server, clock):
    wall = _Wall()
    c = make_client(wall_clock=wall)
    _, cid = _chunk(c)
    server.valid_until = _iso(wall.t + 600)
    assert c.authorize(P, "rag", [cid]).from_cache is False
    n = len(server.requests)
    r = c.authorize(P, "rag", [cid])
    assert r.from_cache and len(server.requests) == n  # served locally while pending is in the future
    wall.t += 700  # effective_at passes; monotonic clock (TTL) and epoch untouched
    server.revoked.add(next(iter(server.envelopes)))  # the server now denies; no epoch bump happened
    r = c.authorize(P, "rag", [cid])
    assert r.from_cache is False and r.decision == "DENY"


def test_allow_inside_skew_window_is_not_cached(make_client, server, clock):
    wall = _Wall()
    c = make_client(wall_clock=wall)
    _, cid = _chunk(c)
    server.valid_until = _iso(wall.t + 10)  # inside the default 30 s skew allowance
    c.authorize(P, "rag", [cid])
    n = len(server.requests)
    c.authorize(P, "rag", [cid])
    assert len(server.requests) > n  # went back to the server


def test_unparseable_valid_until_is_not_cached(make_client, server, clock):
    c = make_client()
    _, cid = _chunk(c)
    server.valid_until = "not-a-date"
    assert c.authorize(P, "rag", [cid]).allowed
    assert len(c.cache) == 0


def test_bounded_offline_denies_protected_past_valid_until(make_client, server, clock):
    wall = _Wall()
    c = _bounded(make_client, wall_clock=wall)
    _, cid = _chunk(c)
    server.valid_until = _iso(wall.t + 3600)
    assert c.authorize(P, "rag", [cid]).decision == "ALLOW"
    server.down = True
    clock.t += 20
    wall.t += 20
    assert c.authorize(P, "rag", [cid]).from_cache  # still before valid_until: bounded offline serves it
    wall.t += 3600  # past valid_until while still within the monotonic lease (snapshot clock unchanged)
    clock.t += 1
    r = c.authorize(P, "rag", [cid])
    assert r.decision == "UNKNOWN" and r.reason == ["POLICY_SNAPSHOT_STALE"] and r.offline


def _ck(i):
    from ales_sdk.decision_cache import make_key

    return make_key("t", "user", "u", "p", f"c{i}", None, "v")


def test_cache_bound_respected_and_get_after_evict_misses():
    from ales_sdk.decision_cache import DecisionCache

    now = [0.0]
    cache = DecisionCache(max_ttl=100, clock=lambda: now[0], max_entries=3)
    assert cache.maxsize == 3
    for i in range(3):
        now[0] += 1
        cache.put(_ck(i), "ALLOW", 0)
    now[0] += 1
    cache.put(_ck(3), "ALLOW", 0)
    assert len(cache) == 3
    assert cache.get(_ck(0)) is None  # earliest expiry evicted
    assert cache.get(_ck(1)) == 0 and cache.get(_ck(3)) == 0
    cache.put(_ck(3), "ALLOW", 0)  # overwrite does not evict
    assert len(cache) == 3


def test_cache_sweeps_expired_before_evicting_live():
    from ales_sdk.decision_cache import DecisionCache

    now = [0.0]
    cache = DecisionCache(max_ttl=100, clock=lambda: now[0], max_entries=3)
    cache.put(_ck(0), "ALLOW", 0, ttl=1)  # will expire
    cache.put(_ck(1), "ALLOW", 0, ttl=50)  # earliest-expiring live entry
    cache.put(_ck(2), "ALLOW", 0, ttl=90)
    now[0] = 5.0
    cache.put(_ck(3), "ALLOW", 0)
    assert len(cache) == 3
    assert cache.get(_ck(1)) == 0 and cache.get(_ck(2)) == 0 and cache.get(_ck(3)) == 0


def test_client_cache_max_entries_kwarg(make_client):
    assert make_client(cache_max_entries=7).cache.maxsize == 7
