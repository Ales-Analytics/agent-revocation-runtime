from ales_sdk import (
    FailMode,
    guard_cache_get,
    guard_memory_read,
    guard_retrieval,
    new_derivative,
    new_source,
)

P = {"type": "user", "id": "alice"}


def _two_chunks(c):
    s1 = new_source("t1", "a", b"a", "kb")
    s2 = new_source("t1", "b", b"b", "kb")
    chunks = []
    for s in (s1, s2):
        c.register_source(s)
        ch = new_derivative("chunk", [s], "t1", s["object_id"] + "#0", b"c")
        c.register_derivation(ch)
        chunks.append(ch)
    return s1, s2, chunks


def test_guard_retrieval_filters_and_taints(make_client):
    c = make_client()
    _, s2, chunks = _two_chunks(c)
    c.submit_revocation({"source_id": s2["context_id"], "reason": "deleted"})
    hits = [{"id": ch["context_id"], "text": "t"} for ch in chunks] + [{"id": "unknown-id", "text": "u"}]
    allowed, blocked = guard_retrieval(c, P, "rag", hits, lambda h: h["id"], session_id="sess")
    assert [h["id"] for h in allowed] == [chunks[0]["context_id"]]
    assert len(blocked) == 2
    by_id = {b.context_id: b for b in blocked}
    assert by_id[chunks[1]["context_id"]].decision == "DENY"
    assert by_id[chunks[1]["context_id"]].reasons == ["ANCESTOR_ACL_REVOKED"]
    assert by_id["unknown-id"].decision == "UNKNOWN"
    assert c.session_taint.contexts_for("sess") == {chunks[0]["context_id"]}


def test_no_session_no_taint(make_client):
    c = make_client()
    _, _, chunks = _two_chunks(c)
    guard_retrieval(c, P, "rag", chunks, lambda h: h["context_id"])
    assert c.session_taint.contexts_for("sess") == set()


def test_observe_mode_passes_everything(make_client, server):
    c = make_client(fail_mode=FailMode.OBSERVE)
    server.deny_all = True
    allowed, blocked = guard_retrieval(c, P, "rag", ["a", "b"], lambda x: x)
    assert allowed == ["a", "b"] and blocked == []


def test_warn_mode_needs_override(make_client, server):
    c = make_client(fail_mode="WARN")
    server.deny_all = True
    _, _, chunks = _two_chunks(c)
    allowed, blocked = guard_memory_read(c, P, "rag", chunks, lambda m: m["context_id"])
    assert allowed == [] and all(b.needs_override for b in blocked)


def test_guard_cache_get(make_client):
    c = make_client()
    s1, _, chunks = _two_chunks(c)
    ids = [ch["context_id"] for ch in chunks]
    val, blocked = guard_cache_get(c, P, "rag", "cached answer", ids, session_id="s")
    assert val == "cached answer" and blocked == []
    c.submit_revocation({"source_id": s1["context_id"], "reason": "deleted"})
    val, blocked = guard_cache_get(c, P, "rag", "cached answer", ids)
    assert val is None and len(blocked) == 1
    assert guard_cache_get(c, P, "rag", None, ids) == (None, [])
