"""SDK correctness ledger: agent-aware cache keys, version-exact batches, versioned taint, policy coupling."""

from ales_sdk import enforce, guard_retrieval, new_source
from ales_sdk.client import AuthorizeResult, ObjectVerdict
from ales_sdk.model_gateway import GuardedModelCall

P = {"type": "user", "id": "alice"}


def _src(c, name="a"):
    s = new_source("t1", name, name.encode(), "kb")
    c.register_source(s)
    return s["context_id"]


def _n_auth(server):
    return len([r for r in server.requests if r[1] == "/v1/authorize"])


# ---- 1. agent_id is part of the cache key ----


def test_allow_cached_for_one_agent_never_serves_another(make_client, server):
    c = make_client()
    cid = _src(c)
    assert c.authorize(P, "rag", [cid], agent_id="agent-a").allowed
    n = _n_auth(server)
    assert c.authorize(P, "rag", [cid], agent_id="agent-a").from_cache  # same agent: cached
    assert _n_auth(server) == n
    server.deny_agents = {"agent-b"}
    r = c.authorize(P, "rag", [cid], agent_id="agent-b")
    assert not r.from_cache and r.decision == "DENY" and _n_auth(server) == n + 1
    assert not c.authorize(P, "rag", [cid]).from_cache  # no agent is a distinct key too


# ---- 2. batches key verdicts by (context_id, version) ----


def test_verdict_for_matches_exact_version():
    objs = [
        ObjectVerdict("c", "ALLOW", ["OK"], "1"),
        ObjectVerdict("c", "DENY", ["REVOKED"], "2"),
    ]
    r = AuthorizeResult("DENY", [], 1, "p", "t", objs)
    assert r.verdict_for("c", "1").decision == "ALLOW"
    assert r.verdict_for("c", "2").decision == "DENY"
    assert r.verdict_for("c", "3") is None  # a different version never rides another's verdict
    assert r.verdict_for("c").decision == "DENY"  # version omitted: most restrictive


def test_mixed_version_batch_maps_and_caches_per_version(make_client, server):
    c = make_client()
    cid = _src(c)
    server.version_aware = True
    server.revoked_versions = {(cid, "1")}
    r = c.authorize(P, "rag", [(cid, "1"), (cid, "2")])  # revoked v1 first, allowed v2 second
    assert r.verdict_for(cid, "1").decision == "DENY"
    assert r.verdict_for(cid, "2").decision == "ALLOW"
    n = _n_auth(server)
    r1 = c.authorize(P, "rag", [(cid, "1")])
    assert r1.decision == "DENY" and not r1.from_cache  # v2's ALLOW must not be cached under v1
    assert _n_auth(server) == n + 1
    assert c.authorize(P, "rag", [(cid, "2")]).from_cache


def test_omitted_version_matches_by_response_version(make_client, server):
    c = make_client()
    cid = _src(c)
    server.version_aware = True
    server.latest_versions = {cid: "7"}
    server.revoked_versions = {(cid, "7")}
    assert c.authorize(P, "rag", [cid]).decision == "DENY"
    server.revoked_versions = set()
    r = c.authorize(P, "rag", [cid])
    assert r.verdict_for(cid, "7").decision == "ALLOW" and r.verdict_for(cid).version == "7"


def test_guard_retrieval_version_exact(make_client, server):
    c = make_client()
    cid = _src(c)
    server.version_aware = True
    server.revoked_versions = {(cid, "2")}
    hits = [{"id": cid, "v": "1"}, {"id": cid, "v": "2"}]
    allowed, blocked = guard_retrieval(
        c, P, "rag", hits, lambda h: h["id"], version_getter=lambda h: h["v"], session_id="s"
    )
    assert allowed == [hits[0]] and [b.item for b in blocked] == [hits[1]]
    assert [(e.context_id, e.version) for e in c.session_taint.exposures_for("s")] == [(cid, "1")]


def test_gateway_prepare_version_exact(make_client, server):
    c = make_client()
    cid = _src(c)
    server.version_aware = True
    server.revoked_versions = {(cid, "2")}
    msgs = [
        {"role": "user", "content": "v1", "ales_context_id": cid, "ales_version": "1"},
        {"role": "user", "content": "v2", "ales_context_id": cid, "ales_version": "2"},
    ]
    prep = GuardedModelCall(c, P, "rag", session_id="g").prepare(msgs)
    assert [m["content"] for m in prep.messages] == ["v1"]
    assert prep.kept == [(cid, "1")] and len(prep.blocked) == 1


# ---- 3. session taint is versioned ----


def test_taint_versions_are_independent(make_client, server):
    c = make_client()
    cid = _src(c)
    server.version_aware = True
    c.session_taint.record("a", [(cid, "1")], principal=P, purpose="rag")
    c.session_taint.record("b", [(cid, "2")], principal=P, purpose="rag")
    c.session_taint.record("both", [(cid, "1"), (cid, "2")], principal=P, purpose="rag")
    server.revoked_versions = {(cid, "2")}
    assert not enforce("a", c).reset_required  # tainted v1 fine while v2 revoked
    assert enforce("b", c).reset_required
    both = enforce("both", c)
    assert both.reset_required and both.checked == 2 and [v.version for v in both.revoked] == ["2"]
    server.revoked_versions = {(cid, "1")}
    c.cache.clear()  # the fake flips revocation without an epoch bump
    assert enforce("a", c).reset_required  # ...and vice versa
    assert not enforce("b", c).reset_required


# ---- 4. a policy_version flip invalidates the held snapshot ----


def test_policy_flip_drops_snapshot_and_offline_cache(make_client, server):
    c = make_client(fail_mode="BOUNDED_OFFLINE", offline_lease_seconds=60)
    a, b = _src(c, "a"), _src(c, "b")
    assert c.authorize(P, "rag", [a]).allowed
    assert c.snapshot is not None and c.snapshot.policy_version == "p1"
    server.policy_version = "p2"
    server.snapshot_status = 500  # the refresh after the flip cannot succeed
    assert c.authorize(P, "rag", [b]).allowed  # response now carries p2
    assert c.snapshot is None  # the p1 snapshot no longer vouches for anything
    server.down = True
    r = c.authorize(P, "rag", [b])
    assert r.decision == "UNKNOWN" and not r.from_cache
