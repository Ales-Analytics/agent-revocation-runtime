import json

import httpx
import pytest
from ales_sdk import (
    BreakerState,
    CircuitBreaker,
    FailMode,
    GuardedModelCall,
    HandoffDenied,
    HumanReviewPending,
    InvariantClient,
    UntrackedContextError,
    new_derivative,
    new_source,
)
from ales_sdk.handoff import handoff

P = {"type": "user", "id": "alice"}


def _chunks(c, n=3):
    out = []
    for i in range(n):
        s = new_source("t1", f"d{i}", b"x%d" % i, "kb")
        c.register_source(s)
        ch = new_derivative("chunk", [s], "t1", f"d{i}#0", b"c")
        c.register_derivation(ch)
        out.append((s, ch))
    return out


def _msgs(chunks):
    return [{"role": "system", "content": "sys"}] + [
        {"role": "user", "content": f"ctx{i}", "ales_context_id": ch["context_id"]}
        for i, (_, ch) in enumerate(chunks)
    ]


def test_prepare_filters_revoked_preserves_order_and_counts_untracked(make_client):
    c = make_client()
    chunks = _chunks(c)
    c.submit_revocation({"source_id": chunks[1][0]["context_id"], "reason": "deleted"})
    g = GuardedModelCall(c, P, "rag", session_id="s1")
    msgs = _msgs(chunks) + [{"role": "user", "content": "meta", "metadata": {"ales_context_id": "nope"}}]
    prepared = g.prepare(msgs)
    assert [m["content"] for m in prepared.messages] == ["sys", "ctx0", "ctx2"]
    assert [b.context_id for b in prepared.blocked] == [chunks[1][1]["context_id"], "nope"]
    s = prepared.decision_summary
    assert (s.total, s.tracked, s.untracked, s.allowed, s.blocked) == (5, 4, 1, 2, 2)
    assert s.coverage == pytest.approx(0.8)
    assert c.session_taint.contexts_for("s1") == {chunks[0][1]["context_id"], chunks[2][1]["context_id"]}


def test_prepare_is_one_batch(make_client, server):
    c = make_client()
    chunks = _chunks(c)
    server.requests.clear()
    GuardedModelCall(c, P, "rag").prepare(_msgs(chunks))
    auths = [b for m, p, b in server.requests if p == "/v1/authorize"]
    assert len(auths) == 1 and len(auths[0]["objects"]) == 3


def test_all_untracked_makes_no_call(make_client, server):
    c = make_client()
    server.requests.clear()
    p = GuardedModelCall(c, P, "rag").prepare([{"role": "user", "content": "hi"}])
    assert p.decision_summary.untracked == 1 and not server.requests and p.messages == []


def test_id_getter(make_client):
    c = make_client()
    chunks = _chunks(c, 1)
    items = [{"id": chunks[0][1]["context_id"]}, {"id": None}]
    p = GuardedModelCall(c, P, "rag", untracked="allow").prepare(items, id_getter=lambda i: i["id"])
    assert len(p.messages) == 2 and p.decision_summary.untracked == 1


@pytest.mark.parametrize(
    ("mode", "kept_revoked", "observed"),
    [
        (FailMode.ENFORCE, False, 0),
        (FailMode.BOUNDED_OFFLINE, False, 0),
        (FailMode.WARN, False, 0),
        (FailMode.OBSERVE, True, 1),
    ],
)
def test_gateway_fail_mode_matrix(make_client, mode, kept_revoked, observed):
    c = make_client(fail_mode=mode)
    chunks = _chunks(c, 2)
    c.submit_revocation({"source_id": chunks[0][0]["context_id"], "reason": "deleted"})
    p = GuardedModelCall(c, P, "rag").prepare(_msgs(chunks)[1:])
    kept_ids = {m["ales_context_id"] for m in p.messages}
    assert (chunks[0][1]["context_id"] in kept_ids) is kept_revoked
    assert chunks[1][1]["context_id"] in kept_ids
    assert p.decision_summary.observed_only == observed
    if mode is FailMode.OBSERVE:
        assert p.blocked == []
    else:
        assert p.blocked[0].decision == "DENY"


def test_gateway_server_down_enforce_removes_all(make_client, server):
    c = make_client(fail_mode=FailMode.ENFORCE, breaker_threshold=0)
    chunks = _chunks(c, 2)
    server.down = True
    p = GuardedModelCall(c, P, "rag").prepare(_msgs(chunks))
    assert [m["content"] for m in p.messages] == ["sys"]
    assert p.decision_summary.offline


def test_wrap_openai_compatible_registers_derivative(make_client, server):
    c = make_client()
    chunks = _chunks(c)
    c.submit_revocation({"source_id": chunks[1][0]["context_id"], "reason": "deleted"})
    seen = {}

    def create(*, messages, model):
        seen["messages"] = messages
        return {"choices": [{"message": {"role": "assistant", "content": "answer"}}]}

    g = GuardedModelCall(c, P, "rag", session_id="s")
    resp, receipt = g.wrap_openai_compatible(create)(messages=_msgs(chunks), model="m")
    assert resp["choices"][0]["message"]["content"] == "answer"
    assert [m["content"] for m in seen["messages"]] == ["sys", "ctx0", "ctx2"]
    assert receipt.registered and receipt.untracked == 1  # the system message
    assert [b.context_id for b in receipt.blocked] == [chunks[1][1]["context_id"]]
    env = server.envelopes[receipt.context_id]
    assert env["kind"] == "artifact"
    assert {p["context_id"] for p in env["parent_refs"]} == {
        chunks[0][1]["context_id"],
        chunks[2][1]["context_id"],
    }
    # revoking a surviving parent's source now denies the response
    c.submit_revocation({"source_id": chunks[0][0]["context_id"], "reason": "deleted"})
    assert c.authorize(P, "rag", [receipt.context_id]).decision == "DENY"


def test_wrap_no_tracked_context_skips_registration(make_client, server):
    c = make_client()
    n = len(server.envelopes)
    _, receipt = GuardedModelCall(c, P, "rag").wrap_openai_compatible(lambda **kw: "x")(
        messages=[{"role": "user", "content": "hi"}]
    )
    assert receipt.context_id is None and receipt.untracked == 1 and len(server.envelopes) == n


def test_wrap_registration_failure_enforce_raises_observe_swallows(make_client, server):
    chunks = _chunks(make_client())
    for mode, raises in ((FailMode.ENFORCE, True), (FailMode.OBSERVE, False)):
        c = make_client(fail_mode=mode, breaker_threshold=0)
        call = GuardedModelCall(c, P, "rag").wrap_openai_compatible(lambda **kw: "x")
        server._faults["/v1/derivations"] = [10, 503]
        if raises:
            with pytest.raises(Exception):  # noqa: B017
                call(messages=_msgs(chunks))
        else:
            _, receipt = call(messages=_msgs(chunks))
            assert not receipt.registered
        server._faults.clear()


def _mixed(chunks):
    ch = [c for _, c in chunks]
    return [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "u0", "ales_context_id": ch[0]["context_id"]},
        {"role": "user", "content": "raw1"},
        {"role": "user", "content": "u2", "ales_context_id": ch[1]["context_id"]},
        {"role": "tool", "content": "raw2"},
    ]


def test_untracked_default_is_protected(make_client):
    c = make_client()
    g = GuardedModelCall(c, P, "rag")
    assert g.untracked == "protected"
    p = g.prepare(_mixed(_chunks(c, 2)))
    assert [m["content"] for m in p.messages] == ["sys", "u0", "u2"]
    assert [b.item["content"] for b in p.blocked_untracked] == ["raw1", "raw2"]
    assert p.decision_summary.blocked_untracked == 2


def test_untracked_allow_explicit_passes_and_warns_once(make_client, caplog):
    c = make_client()
    g = GuardedModelCall(c, P, "rag", untracked="allow")
    msgs = _mixed(_chunks(c, 2))
    with caplog.at_level("WARNING", logger="ales_sdk"):
        p1 = g.prepare(msgs)
        p2 = g.prepare(msgs)
    assert len(p1.messages) == 5 and p1.blocked_untracked == []
    assert len(p2.messages) == 5
    warns = [r for r in caplog.records if "untracked" in r.getMessage()]
    assert len(warns) == 1
    s = p1.decision_summary
    assert (s.untracked, s.exempt, s.blocked_untracked) == (3, 1, 0)


def test_untracked_allow_no_warning_when_only_exempt(make_client, caplog):
    c = make_client()
    with caplog.at_level("WARNING", logger="ales_sdk"):
        GuardedModelCall(c, P, "rag", untracked="allow").prepare([{"role": "system", "content": "s"}])
    assert not caplog.records


def test_untracked_deny_removes_preserves_order(make_client):
    c = make_client()
    g = GuardedModelCall(c, P, "rag", untracked="deny")
    p = g.prepare(_mixed(_chunks(c, 2)))
    assert [m["content"] for m in p.messages] == ["sys", "u0", "u2"]
    assert [b.item["content"] for b in p.blocked_untracked] == ["raw1", "raw2"]
    assert all(b.reasons == ["UNTRACKED_CONTEXT"] and b.decision == "DENY" for b in p.blocked_untracked)
    assert p.blocked == []
    s = p.decision_summary
    assert (s.total, s.tracked, s.untracked, s.blocked_untracked) == (5, 2, 3, 2)
    assert s.coverage == pytest.approx(0.4)


def test_untracked_deny_all_untracked_no_authorize_call(make_client, server):
    c = make_client()
    server.requests.clear()
    p = GuardedModelCall(c, P, "rag", untracked="deny").prepare(
        [{"role": "user", "content": "a"}, {"role": "system", "content": "s"}]
    )
    assert [m["content"] for m in p.messages] == ["s"] and not server.requests


def test_untracked_error_lists_indices_and_makes_no_call(make_client, server):
    c = make_client()
    msgs = _mixed(_chunks(c, 2))
    server.requests.clear()
    with pytest.raises(UntrackedContextError) as ei:
        GuardedModelCall(c, P, "rag", untracked="error").prepare(msgs)
    assert ei.value.indices == [2, 4] and not server.requests
    ok = GuardedModelCall(c, P, "rag", untracked="error").prepare(msgs[:2] + msgs[3:4])
    assert len(ok.messages) == 3


def test_untracked_invalid_mode():
    with pytest.raises(Exception, match="untracked"):
        GuardedModelCall(None, P, "rag", untracked="nope")  # type: ignore[arg-type]


@pytest.mark.parametrize("mode", ["protected", "deny", "error"])
def test_untracked_observe_never_blocks(make_client, mode):
    c = make_client(fail_mode=FailMode.OBSERVE)
    p = GuardedModelCall(c, P, "rag", untracked=mode).prepare(_mixed(_chunks(c, 2)))
    assert len(p.messages) == 5 and p.blocked_untracked == [] and p.blocked == []
    assert p.decision_summary.observed_only == 2 and p.decision_summary.blocked_untracked == 0


def test_exempt_roles_default_and_override(make_client):
    c = make_client()
    msgs = [
        {"role": "system", "content": "s"},
        {"role": "developer", "content": "d"},
        {"role": "user", "content": "u"},
    ]
    p = GuardedModelCall(c, P, "rag", untracked="deny").prepare(msgs)
    assert [m["content"] for m in p.messages] == ["s"]  # developer not exempt by default
    p = GuardedModelCall(c, P, "rag", untracked="deny", exempt_roles=("system", "developer")).prepare(msgs)
    assert [m["content"] for m in p.messages] == ["s", "d"]
    p = GuardedModelCall(c, P, "rag", untracked="deny", exempt_roles=()).prepare(msgs)
    assert p.messages == []
    # non-dict items are never exempt
    p = GuardedModelCall(c, P, "rag", untracked="deny").prepare(["plain"])
    assert p.messages == []


def test_trusted_roles_source_none_ignores_exempt_roles(make_client):
    c = make_client()
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    p = GuardedModelCall(c, P, "rag", trusted_roles_source="none").prepare(msgs)
    assert p.messages == [] and p.decision_summary.exempt == 0
    with pytest.raises(Exception, match="trusted_roles_source"):
        GuardedModelCall(c, P, "rag", trusted_roles_source="bogus")


@pytest.mark.parametrize("mode", ["protected", "allow", "deny", "error"])
def test_revoked_item_labelled_system_with_ales_id_still_blocked(make_client, mode):
    c = make_client()
    chunks = _chunks(c, 1)
    c.submit_revocation({"source_id": chunks[0][0]["context_id"], "reason": "deleted"})
    msgs = [{"role": "system", "content": "spoof", "ales_context_id": chunks[0][1]["context_id"]}]
    p = GuardedModelCall(c, P, "rag", untracked=mode).prepare(msgs)
    assert p.messages == [] and [b.context_id for b in p.blocked] == [chunks[0][1]["context_id"]]
    meta = [
        {"role": "system", "content": "spoof", "metadata": {"ales_context_id": chunks[0][1]["context_id"]}}
    ]
    assert GuardedModelCall(c, P, "rag", untracked=mode).prepare(meta).messages == []


def test_system_item_with_other_ales_marker_is_not_exempt(make_client):
    c = make_client()
    msgs = [{"role": "system", "content": "s", "ales_version": "1"}]
    p = GuardedModelCall(c, P, "rag").prepare(msgs)
    assert p.messages == [] and p.decision_summary.exempt == 0


def test_wrap_deny_receipt_counts_and_sends_filtered(make_client):
    c = make_client()
    seen = {}

    def create(*, messages):
        seen["m"] = messages
        return "x"

    g = GuardedModelCall(c, P, "rag", untracked="deny")
    _, receipt = g.wrap_openai_compatible(create)(messages=_mixed(_chunks(c, 2)))
    assert [m["content"] for m in seen["m"]] == ["sys", "u0", "u2"]
    assert receipt.untracked_blocked == 2 and receipt.untracked == 3 and receipt.registered


def test_wrap_error_mode_never_calls_model(make_client):
    c = make_client()
    called = []
    g = GuardedModelCall(c, P, "rag", untracked="error")
    with pytest.raises(UntrackedContextError):
        g.wrap_openai_compatible(lambda **kw: called.append(1))(messages=_mixed(_chunks(c, 2)))
    assert not called


def _hr_client(make_client, mode=FailMode.ENFORCE):
    def handler(request):
        body = json.loads(request.content)
        objs = [
            {"context_id": o["context_id"], "decision": "HUMAN_REVIEW", "reason": ["POLICY_HUMAN_REVIEW"]}
            if o["context_id"] == "hr"
            else {"context_id": o["context_id"], "decision": "ALLOW", "reason": ["OK"]}
            for o in body["objects"]
        ]
        return httpx.Response(
            200,
            json={
                "decision": "HUMAN_REVIEW",
                "reason": ["POLICY_HUMAN_REVIEW"],
                "revocation_epoch": 0,
                "policy_version": "p1",
                "trace_id": "t",
                "objects": objs,
            },
        )

    return InvariantClient("http://x", "t1", "tok", fail_mode=mode, transport=httpx.MockTransport(handler))


def test_human_review_raises_under_enforce(make_client):
    g = GuardedModelCall(_hr_client(make_client), P, "rag")
    with pytest.raises(HumanReviewPending) as ei:
        g.prepare([{"ales_context_id": "hr"}, {"ales_context_id": "ok"}])
    assert ei.value.context_ids == ["hr"] and "POLICY_HUMAN_REVIEW" in ei.value.approval_hint


def test_human_review_block_item(make_client):
    g = GuardedModelCall(_hr_client(make_client), P, "rag", on_human_review="block_item")
    p = g.prepare([{"ales_context_id": "hr"}, {"ales_context_id": "ok"}])
    assert [m["ales_context_id"] for m in p.messages] == ["ok"]
    assert p.blocked[0].decision == "HUMAN_REVIEW"


def test_human_review_observe_keeps(make_client):
    g = GuardedModelCall(_hr_client(make_client, FailMode.OBSERVE), P, "rag")
    p = g.prepare([{"ales_context_id": "hr"}])
    assert len(p.messages) == 1 and p.decision_summary.observed_only == 1


class CountingTransport(httpx.BaseTransport):
    def __init__(self):
        self.calls = 0
        self.fail = True

    def handle_request(self, request):
        self.calls += 1
        if self.fail:
            raise httpx.ConnectError("down", request=request)
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "decision": "ALLOW",
                "reason": ["OK"],
                "revocation_epoch": 1,
                "policy_version": "p1",
                "trace_id": "t",
                "objects": [
                    {"context_id": o["context_id"], "decision": "ALLOW", "reason": ["OK"]}
                    for o in body["objects"]
                ],
            },
        )


def test_breaker_opens_fails_fast_and_recovers(clock):
    tr = CountingTransport()
    c = InvariantClient(
        "http://x",
        "t1",
        "tok",
        transport=tr,
        max_retries=0,
        clock=clock,
        breaker_threshold=3,
        breaker_recovery=10.0,
    )
    for _ in range(3):
        r = c.authorize(P, "p", ["a"])
        assert r.decision == "UNKNOWN" and r.reason == ["POLICY_SNAPSHOT_STALE"] and r.offline
    assert c.breaker_state is BreakerState.OPEN and tr.calls == 3
    for _ in range(5):
        r = c.authorize(P, "p", ["a"])
        assert r.decision == "UNKNOWN" and r.offline
    assert tr.calls == 3  # fail fast: nothing hit the transport
    clock.t += 11
    r = c.authorize(P, "p", ["a"])  # failed probe re-opens
    assert tr.calls == 4 and c.breaker_state is BreakerState.OPEN
    c.authorize(P, "p", ["a"])
    assert tr.calls == 4
    clock.t += 11
    tr.fail = False
    assert c.authorize(P, "p", ["a"]).decision == "ALLOW"
    assert c.breaker_state is BreakerState.CLOSED and tr.calls == 5


def test_breaker_disabled(clock):
    tr = CountingTransport()
    c = InvariantClient(
        "http://x", "t1", "tok", transport=tr, max_retries=0, clock=clock, breaker_threshold=0
    )
    for _ in range(10):
        c.authorize(P, "p", ["a"])
    assert tr.calls == 10 and c.breaker_state is None


def test_breaker_resets_on_success_and_half_open_single_probe():
    t = [0.0]
    b = CircuitBreaker(2, 5.0, clock=lambda: t[0])
    b.record_failure()
    b.record_success()
    b.record_failure()
    assert b.state is BreakerState.CLOSED
    b.record_failure()
    assert b.state is BreakerState.OPEN and not b.allow()
    t[0] = 6.0
    assert b.allow() is True  # the probe
    assert b.state is BreakerState.HALF_OPEN and b.allow() is False  # no second probe
    b.record_success()
    assert b.state is BreakerState.CLOSED and b.allow()


def test_http_error_does_not_trip_breaker(clock):
    c = InvariantClient(
        "http://x",
        "t1",
        "tok",
        max_retries=0,
        clock=clock,
        breaker_threshold=1,
        transport=httpx.MockTransport(lambda r: httpx.Response(400, json={"detail": "bad"})),
    )
    for _ in range(3):
        with pytest.raises(Exception):  # noqa: B017
            c.authorize(P, "p", ["a"])
    assert c.breaker_state is BreakerState.CLOSED


def test_handoff_local_taint_transfer(make_client):
    c = make_client()
    c.session_taint.record("a", ["x", "y"], principal=P, purpose="rag")
    res = handoff(c, "a", "b", purpose="rag")
    assert res.context_ids == {"x", "y"} and res.exposures_copied == 2 and res.decision is None
    assert c.session_taint.contexts_for("b") == {"x", "y"}
    assert c.session_taint.contexts_for("a") == {"x", "y"}


def _handoff_client(response, mode=FailMode.ENFORCE):
    calls = []

    def handler(request):
        calls.append((request.url.path, json.loads(request.content)))
        return response(request)

    c = InvariantClient("http://x", "t1", "tok", fail_mode=mode, transport=httpx.MockTransport(handler))
    c.session_taint.record("a", ["x"], principal=P, purpose="rag")
    return c, calls


def test_handoff_allow_sends_contract_body():
    c, calls = _handoff_client(lambda r: httpx.Response(200, json={"decision": "ALLOW", "reason": ["OK"]}))
    res = handoff(c, "a", "b", from_workload="w1", to_workload="w2", purpose="rag")
    assert calls == [("/v1/handoffs", {"from_workload": "w1", "to_workload": "w2", "purpose": "rag"})]
    assert res.decision == "ALLOW" and c.session_taint.contexts_for("b") == {"x"}


def test_handoff_deny_raises_and_does_not_transfer():
    c, _ = _handoff_client(
        lambda r: httpx.Response(200, json={"decision": "DENY", "reason": ["DELEGATION_MISSING"]})
    )
    with pytest.raises(HandoffDenied) as ei:
        handoff(c, "a", "b", from_workload="w1", to_workload="w2", purpose="rag")
    assert ei.value.reasons == ["DELEGATION_MISSING"]
    assert c.session_taint.contexts_for("b") == set()


def test_handoff_404_is_unknown_failmode_applied():
    notfound = lambda r: httpx.Response(404, json={"error": "not found"})
    c, _ = _handoff_client(notfound)
    with pytest.raises(HandoffDenied) as ei:
        handoff(c, "a", "b", from_workload="w1", to_workload="w2", purpose="rag")
    assert ei.value.reasons == ["HANDOFF_ENDPOINT_UNAVAILABLE"]
    c2, _ = _handoff_client(notfound, FailMode.OBSERVE)
    res = handoff(c2, "a", "b", from_workload="w1", to_workload="w2", purpose="rag")
    assert res.decision == "UNKNOWN" and c2.session_taint.contexts_for("b") == {"x"}


def test_handoff_human_review_raises():
    c, _ = _handoff_client(
        lambda r: httpx.Response(200, json={"decision": "HUMAN_REVIEW", "reason": ["APPROVAL_PENDING"]})
    )
    with pytest.raises(HumanReviewPending):
        handoff(c, "a", "b", from_workload="w1", to_workload="w2", purpose="rag")


def _capture_client():
    bodies = []

    def handler(request):
        body = json.loads(request.content)
        bodies.append(body)
        return httpx.Response(
            200,
            json={
                "decision": "ALLOW",
                "reason": ["OK"],
                "revocation_epoch": 1,
                "policy_version": "p1",
                "trace_id": "t",
                "objects": [
                    {"context_id": o["context_id"], "decision": "ALLOW", "reason": ["OK"]}
                    for o in body["objects"]
                ],
            },
        )

    return InvariantClient("http://x", "t1", "tok", transport=httpx.MockTransport(handler)), bodies


def test_tools_risk_passthrough_and_omitted_when_empty():
    c, bodies = _capture_client()
    c.authorize(P, "p", ["a"], tools=["web_search"], risk="high")
    assert bodies[0]["tools"] == ["web_search"] and bodies[0]["risk"] == "high"
    c.authorize(P, "p", ["b"], tools=[], risk=None)
    assert "tools" not in bodies[1] and "risk" not in bodies[1]


def test_scoped_requests_bypass_decision_cache():
    c, bodies = _capture_client()
    c.authorize(P, "p", ["a"])
    c.authorize(P, "p", ["a"])  # cached, no request
    assert len(bodies) == 1
    c.authorize(P, "p", ["a"], risk="high")
    c.authorize(P, "p", ["a"], risk="high")
    assert len(bodies) == 3
