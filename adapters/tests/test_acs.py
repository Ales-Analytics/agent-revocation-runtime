import pytest
from ales_adapters.acs_adapter import HOOKS, AcsContextGuard, AcsPayloadError, HookDecision
from ales_sdk import new_derivative, new_source


def ctx(**over):
    c = {
        "tenant": "t1",
        "principal": {"type": "user", "id": "alice"},
        "purpose": "support",
        "session_id": "s1",
        "agent_id": "agent-1",
    }
    c.update(over)
    return c


def _chunks(client, n=2):
    srcs = [new_source("t1", f"d{i}", f"c{i}", "test") for i in range(n)]
    docs = []
    for s in srcs:
        client.register_source(s)
        d = new_derivative("chunk", [s], "t1", "chunk", "x")
        client.register_derivation(d)
        docs.append({"context_id": d["context_id"], "version": d["object_version"], "text": "x"})
    return srcs, docs


@pytest.fixture
def guard(client):
    return AcsContextGuard(client)


def test_hook_decision_validation_and_wire_form():
    d = HookDecision(True, ["OK"])
    assert d.to_dict() == {"allow": True, "reasons": ["OK"], "required_action": "none", "data": {}}
    with pytest.raises(ValueError):
        HookDecision(True, [], "explode")


def test_retrieval_hooks_happy_path_and_redaction(client, guard):
    srcs, docs = _chunks(client)
    assert guard.before_knowledge_retrieval(ctx()).allow
    d = guard.after_knowledge_retrieval(ctx(), docs)
    assert d.allow and d.required_action == "none" and d.data["results"] == docs
    assert client.session_taint.contexts_for("s1") == {x["context_id"] for x in docs}

    client.submit_revocation({"source_id": srcs[0]["context_id"], "reason": "deleted"})
    d = guard.after_knowledge_retrieval(ctx(session_id="s2"), docs)
    assert d.allow and d.required_action == "redact" and d.data["results"] == [docs[1]]
    assert d.data["blocked"][0]["context_id"] == docs[0]["context_id"] and "ANCESTOR_ACL_REVOKED" in d.reasons


def test_before_retrieval_denies_a_tainted_session(client, guard):
    srcs, docs = _chunks(client)
    guard.after_knowledge_retrieval(ctx(), docs)
    client.submit_revocation({"source_id": srcs[1]["context_id"], "reason": "deleted"})
    d = guard.before_knowledge_retrieval(ctx())
    assert not d.allow and d.required_action == "session_reset"
    assert d.data["revoked_context_ids"] == [docs[1]["context_id"]]


def test_memory_read_filters_keys(client, guard):
    srcs, docs = _chunks(client)
    keys = [{"key": "k0", "context_id": docs[0]["context_id"], "version": "1"}, docs[1]["context_id"]]
    d = guard.before_memory_read(ctx(), keys)
    assert d.allow and d.required_action == "none" and d.data["keys"] == keys
    client.submit_revocation({"source_id": srcs[0]["context_id"], "reason": "deleted"})
    d = guard.before_memory_read(ctx(), keys)
    assert d.allow and d.required_action == "redact" and d.data["keys"] == [keys[1]]


def test_memory_write_registers_derivatives_with_active_parents(client, guard):
    srcs, docs = _chunks(client)
    active = [{"context_id": x["context_id"], "version": "1"} for x in docs]
    d = guard.after_memory_write(ctx(active_context_ids=active), [{"key": "m1", "content": "note"}])
    assert d.allow and len(d.data["registered"]) == 1
    rec = d.data["registered"][0]
    assert rec["key"] == "m1"
    # the memory is readable until either parent is revoked, then denied (parent lineage is right)
    r = client.authorize({"type": "user", "id": "alice"}, "support", [(rec["context_id"], rec["version"])])
    assert r.verdict_for(rec["context_id"]).decision == "ALLOW"
    client.submit_revocation({"source_id": srcs[1]["context_id"], "reason": "deleted"})
    r = client.authorize({"type": "user", "id": "alice"}, "support", [(rec["context_id"], rec["version"])])
    assert r.verdict_for(rec["context_id"]).decision == "DENY"
    assert not guard.before_memory_read(ctx(), [rec["context_id"]]).data["keys"]


def test_memory_write_falls_back_to_session_taint_and_handles_no_context(client, guard):
    srcs, docs = _chunks(client, 1)
    none = guard.after_memory_write(ctx(session_id="empty"), [{"key": "m", "content": "c"}])
    assert none.allow and none.reasons == ["NO_ACTIVE_CONTEXT"] and none.data["registered"] == []
    guard.after_knowledge_retrieval(ctx(), docs)
    d = guard.after_memory_write(ctx(), [{"key": "m", "content": "c"}])
    rec = d.data["registered"][0]
    client.submit_revocation({"source_id": srcs[0]["context_id"], "reason": "deleted"})
    r = client.authorize({"type": "user", "id": "alice"}, "support", [(rec["context_id"], rec["version"])])
    assert r.verdict_for(rec["context_id"]).decision == "DENY"


def test_clean_session_tool_and_message_allowed(client, guard):
    _, docs = _chunks(client)
    guard.after_knowledge_retrieval(ctx(), docs)
    assert guard.before_tool_call(ctx(), "search", {"q": "x"}).allow
    assert guard.before_message_send(ctx(), "hello").allow
    assert guard.before_message_send(ctx(), {"text": "hello"}).allow


def test_revoked_session_tool_call_and_message_denied_with_session_reset(client, guard):
    srcs, docs = _chunks(client)
    guard.after_knowledge_retrieval(ctx(), docs)
    client.submit_revocation({"source_id": srcs[0]["context_id"], "reason": "acl_changed"})
    for d in (guard.before_tool_call(ctx(), "send_email", {"to": "x"}), guard.before_message_send(ctx(), "hi")):
        assert not d.allow and d.required_action == "session_reset"
        assert "ANCESTOR_ACL_REVOKED" in d.reasons
    # other sessions are unaffected
    assert guard.before_tool_call(ctx(session_id="other"), "t", {}).allow


def test_declared_active_context_is_enforced_without_prior_retrieval(client, guard):
    srcs, docs = _chunks(client, 1)
    client.submit_revocation({"source_id": srcs[0]["context_id"], "reason": "deleted"})
    d = guard.before_tool_call(ctx(active_context_ids=[docs[0]["context_id"]]), "t", {})
    assert not d.allow and d.required_action == "session_reset"


def test_tenant_mismatch_denied(guard):
    for d in (
        guard.before_knowledge_retrieval(ctx(tenant="other")),
        guard.after_knowledge_retrieval(ctx(tenant="other"), []),
        guard.before_tool_call(ctx(tenant="other"), "t", {}),
    ):
        assert not d.allow and d.reasons == ["TENANT_MISMATCH"]


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        ctx(principal="alice"),
        ctx(principal={"type": "user"}),
        ctx(purpose=""),
        ctx(session_id=5),
        ctx(extra="x"),
        ctx(active_context_ids="abc"),
        ctx(active_context_ids=[5]),
    ],
)
def test_malformed_ctx_raises(guard, bad):
    with pytest.raises(AcsPayloadError):
        guard.before_knowledge_retrieval(bad)
    d = guard.handle("before_knowledge_retrieval", {"ctx": bad})
    assert not d.allow and d.error["code"] == "INVALID_PAYLOAD"


def test_malformed_hook_payloads_raise(guard):
    with pytest.raises(AcsPayloadError):
        guard.after_knowledge_retrieval(ctx(), "not-a-list")
    with pytest.raises(AcsPayloadError):
        guard.after_knowledge_retrieval(ctx(), [{"no_context_id": 1}])
    with pytest.raises(AcsPayloadError):
        guard.after_knowledge_retrieval(ctx(), ["bare-string"])
    with pytest.raises(AcsPayloadError):
        guard.before_memory_read(ctx(), [{"context_id": "a", "version": 1}])
    with pytest.raises(AcsPayloadError):
        guard.after_memory_write(ctx(), [{"key": "k"}])
    with pytest.raises(AcsPayloadError):
        guard.before_tool_call(ctx(), "", {})
    with pytest.raises(AcsPayloadError):
        guard.before_tool_call(ctx(), "t", ["args"])
    with pytest.raises(AcsPayloadError):
        guard.before_message_send(ctx(), 42)


def test_dispatcher_routes_every_hook(client, guard):
    _, docs = _chunks(client)
    payloads = {
        "before_knowledge_retrieval": {"ctx": ctx()},
        "after_knowledge_retrieval": {"ctx": ctx(), "results": docs},
        "before_memory_read": {"ctx": ctx(), "keys": [docs[0]["context_id"]]},
        "after_memory_write": {"ctx": ctx(), "entries": [{"key": "k", "content": "c"}]},
        "before_tool_call": {"ctx": ctx(), "tool": "t", "args": {}},
        "before_message_send": {"ctx": ctx(), "message": "m"},
    }
    assert set(payloads) == set(HOOKS)
    for name, p in payloads.items():
        d = guard.handle(name, p)
        assert d.allow and d.error is None, name
        assert d.to_dict()["required_action"] == "none"


def test_dispatcher_fails_closed(client, guard):
    d = guard.handle("before_coffee", {"ctx": ctx()})
    assert not d.allow and d.error["code"] == "UNKNOWN_HOOK"
    assert not guard.handle(None, {}).allow
    assert guard.handle("before_tool_call", {"ctx": ctx(), "tool": "t"}).error["code"] == "INVALID_PAYLOAD"  # missing args
    assert guard.handle("before_tool_call", {"ctx": ctx(), "tool": "t", "args": {}, "x": 1}).error["code"] == "INVALID_PAYLOAD"
    assert guard.handle("before_tool_call", "nope").error["code"] == "INVALID_PAYLOAD"
    assert guard.handle("before_message_send", {"ctx": ctx(), "message": 5}).error["code"] == "INVALID_PAYLOAD"


def test_dispatcher_internal_error_denies(client, guard, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(guard, "before_tool_call", boom)
    d = guard.handle("before_tool_call", {"ctx": ctx(), "tool": "t", "args": {}})
    assert not d.allow and d.error["code"] == "INTERNAL_ERROR"


def test_control_plane_error_during_enforcement_is_a_deny(client, guard, monkeypatch):
    from ales_sdk import AlesConnectionError

    _, docs = _chunks(client, 1)
    guard.after_knowledge_retrieval(ctx(), docs)

    def down(*a, **k):
        raise AlesConnectionError("down")

    monkeypatch.setattr(client, "authorize", down)
    d = guard.before_tool_call(ctx(), "t", {})
    assert not d.allow and d.required_action == "session_reset" and "ENFORCEMENT_ERROR" in d.reasons
    d = guard.after_knowledge_retrieval(ctx(session_id="n"), docs)
    assert not d.allow and d.data["results"] == []
