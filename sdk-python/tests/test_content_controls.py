import pytest
from ales_sdk import (
    BedrockGuardrailControl,
    ContentAssessment,
    ContentBlocked,
    ContentControlPolicy,
    FailMode,
    GuardedModelCall,
    SimulatedContentControl,
    digest,
    new_derivative,
    new_source,
)

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


def _msgs(chunks, texts):
    return [{"role": "system", "content": "sys"}] + [
        {"role": "user", "content": t, "ales_context_id": ch["context_id"]}
        for t, (_, ch) in zip(texts, chunks, strict=True)
    ]


def _resp(text):
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


# -- Bedrock mapping ----------------------------------------------------------------------------
def _bedrock(resp):
    return BedrockGuardrailControl(lambda content, source: resp, "gr-1", "3")


def test_bedrock_mapping_matrix():
    none = _bedrock({"action": "NONE", "outputs": [], "assessments": []}).assess_input("hi")
    assert none.action == "none" and none.masked_text is None
    masked = _bedrock(
        {
            "action": "GUARDRAIL_INTERVENED",
            "outputs": [{"text": "call {PHONE}"}],
            "assessments": [
                {
                    "sensitiveInformationPolicy": {
                        "piiEntities": [{"type": "PHONE", "action": "ANONYMIZED", "match": "555-1234"}]
                    }
                }
            ],
        }
    ).assess_output("call 555-1234")
    assert masked.action == "masked" and masked.masked_text == "call {PHONE}"
    assert "555-1234" not in repr(masked) and "555-1234" not in str(masked.detail)
    no_out = _bedrock({"action": "GUARDRAIL_INTERVENED", "outputs": [], "assessments": []}).assess_input("x")
    assert no_out.action == "blocked"
    canned = _bedrock(
        {
            "action": "GUARDRAIL_INTERVENED",
            "outputs": [{"text": "Sorry, blocked."}],
            "assessments": [{"topicPolicy": {"topics": [{"name": "t", "action": "BLOCKED"}]}}],
        }
    ).assess_input("x")
    assert canned.action == "blocked"
    assert (masked.provider, masked.guardrail_version) == ("bedrock-guardrails", "3")
    assert masked.detail["guardrail_id"] == "gr-1" and masked.reference.startswith("sha256:")
    again = _bedrock(
        {
            "action": "GUARDRAIL_INTERVENED",
            "outputs": [{"text": "call {PHONE}"}],
            "assessments": [
                {
                    "sensitiveInformationPolicy": {
                        "piiEntities": [{"type": "PHONE", "action": "ANONYMIZED", "match": "other"}]
                    }
                }
            ],
        }
    ).assess_output("different")
    assert again.reference == masked.reference  # stable over assessment detail, not text


def test_bedrock_passes_source_and_text_only_via_callable():
    calls = []

    def fn(content, source):
        calls.append((content, source))
        return {"action": "NONE"}

    ctl = BedrockGuardrailControl(fn, "g", "1")
    ctl.assess_input("a")
    ctl.assess_output("b")
    assert calls == [("a", "INPUT"), ("b", "OUTPUT")]


# -- policy ---------------------------------------------------------------------------------------
def _boom(text):
    raise RuntimeError("secret text in message")


def test_policy_required_vs_optional_failure():
    req = ContentControlPolicy(required=True).run(_boom, "t", "p")
    assert req.action == "blocked" and req.detail["reason"] == "provider_unavailable"
    assert "secret" not in str(req.detail)
    opt = ContentControlPolicy(required=False).run(_boom, "t", "p")
    assert opt.action == "none" and opt.detail["reason"] == "provider_unavailable"


class _Failing:
    provider = "failing"

    def assess_input(self, text):
        raise RuntimeError("down")

    assess_output = assess_input


def test_required_failure_blocks_input_and_output(make_client):
    c = make_client()
    chunks = _chunks(c, 1)
    g = GuardedModelCall(c, P, "rag", input_control=_Failing(), output_control=_Failing())
    p = g.prepare(_msgs(chunks, ["a"]))
    assert [m["content"] for m in p.messages] == []  # system + tracked both blocked: fail closed
    assert p.decision_summary.content_blocked == 2
    with pytest.raises(ContentBlocked) as ei:
        g.wrap_openai_compatible(lambda **kw: _resp("x"))(messages=_msgs(chunks, ["a"]))
    assert ei.value.assessment.detail["reason"] == "provider_unavailable"


def test_optional_failure_records_and_passes(make_client):
    c = make_client()
    chunks = _chunks(c, 1)
    g = GuardedModelCall(
        c,
        P,
        "rag",
        input_control=_Failing(),
        output_control=_Failing(),
        control_policy=ContentControlPolicy(required=False),
    )
    resp, receipt = g.wrap_openai_compatible(lambda **kw: _resp("x"))(messages=_msgs(chunks, ["a"]))
    assert resp == _resp("x") and receipt.registered
    assert receipt.content_assessments and all(a.action == "none" for a in receipt.content_assessments)
    assert all(a.detail["reason"] == "provider_unavailable" for a in receipt.content_assessments)


# -- input stage --------------------------------------------------------------------------------
def test_input_blocked_item_removed_and_counted(make_client):
    c = make_client()
    chunks = _chunks(c)
    ctl = SimulatedContentControl(deny=[r"FORBIDDEN"])
    g = GuardedModelCall(c, P, "rag", session_id="s", input_control=ctl)
    p = g.prepare(_msgs(chunks, ["ok0", "FORBIDDEN stuff", "ok2"]))
    assert [m["content"] for m in p.messages] == ["sys", "ok0", "ok2"]
    assert p.decision_summary.content_blocked == 1
    assert [a.action for a in p.content_assessments] == ["blocked"]
    assert p.content_assessments[0].provider == "simulated"
    assert "FORBIDDEN" not in str(p.content_assessments[0].detail.get("context_id"))
    # authority view unchanged: content block is not an authority block
    assert p.blocked == [] and p.decision_summary.blocked == 0
    # blocked item is not a parent and is not recorded as consumed
    assert chunks[1][1]["context_id"] not in {k[0] for k in p.kept}
    assert c.session_taint.contexts_for("s") == {chunks[0][1]["context_id"], chunks[2][1]["context_id"]}


def test_input_masked_keeps_ales_ids_and_parents(make_client, server):
    c = make_client()
    chunks = _chunks(c, 2)
    ctl = SimulatedContentControl(mask=[r"\d{3}-\d{4}"])
    g = GuardedModelCall(c, P, "rag", input_control=ctl)
    msgs = _msgs(chunks, ["call 555-1234", "clean"])
    p = g.prepare(msgs)
    assert p.messages[1]["content"] == "call [MASKED]"
    assert p.messages[1]["ales_context_id"] == chunks[0][1]["context_id"]
    assert msgs[1]["content"] == "call 555-1234"  # caller's list not mutated
    assert p.decision_summary.content_masked == 1
    assert {k[0] for k in p.kept} == {ch["context_id"] for _, ch in chunks}
    _, receipt = g.wrap_openai_compatible(lambda **kw: _resp("ans"))(messages=msgs)
    env = server.envelopes[receipt.context_id]
    assert {x["context_id"] for x in env["parent_refs"]} == {ch["context_id"] for _, ch in chunks}


# -- output stage -------------------------------------------------------------------------------
def test_output_masked_registers_masked_text_with_original_parents(make_client, server):
    c = make_client()
    chunks = _chunks(c, 2)
    g = GuardedModelCall(c, P, "rag", output_control=SimulatedContentControl(mask=[r"\d{3}-\d{4}"]))
    resp, receipt = g.wrap_openai_compatible(lambda **kw: _resp("tel 555-1234"))(
        messages=_msgs(chunks, ["a", "b"])
    )
    assert resp["choices"][0]["message"]["content"] == "tel [MASKED]"
    env = server.envelopes[receipt.context_id]
    assert env["content_digest"] == digest("tel [MASKED]")
    assert {x["context_id"] for x in env["parent_refs"]} == {ch["context_id"] for _, ch in chunks}
    assert [a.action for a in receipt.content_assessments] == ["masked"]
    assert all(a.masked_text is None for a in receipt.content_assessments)
    # masking is not declassification: revoking a parent still denies the masked artifact
    c.submit_revocation({"source_id": chunks[0][0]["context_id"], "reason": "deleted"})
    assert c.authorize(P, "rag", [receipt.context_id]).decision == "DENY"


def test_output_blocked_raises_under_enforce_records_under_observe(make_client, server):
    chunks = _chunks(make_client(), 1)
    ctl = SimulatedContentControl(deny=[r"BAD"])
    g = GuardedModelCall(make_client(), P, "rag", output_control=ctl)
    n = len(server.envelopes)
    with pytest.raises(ContentBlocked) as ei:
        g.wrap_openai_compatible(lambda **kw: _resp("BAD answer"))(messages=_msgs(chunks, ["a"]))
    assert ei.value.assessment.action == "blocked" and "BAD" not in str(ei.value)
    assert len(server.envelopes) == n  # nothing registered

    go = GuardedModelCall(make_client(fail_mode=FailMode.OBSERVE), P, "rag", output_control=ctl)
    resp, receipt = go.wrap_openai_compatible(lambda **kw: _resp("BAD answer"))(messages=_msgs(chunks, ["a"]))
    assert resp["choices"][0]["message"]["content"] == "BAD answer"
    assert [a.action for a in receipt.content_assessments] == ["blocked"] and receipt.registered


def test_observe_does_not_alter_input(make_client):
    c = make_client(fail_mode=FailMode.OBSERVE)
    chunks = _chunks(c, 2)
    ctl = SimulatedContentControl(deny=[r"BAD"], mask=[r"\d+"])
    p = GuardedModelCall(c, P, "rag", input_control=ctl).prepare(_msgs(chunks, ["BAD", "n 42"]))
    assert [m["content"] for m in p.messages] == ["sys", "BAD", "n 42"]
    assert len(p.content_assessments) == 2 and p.decision_summary.content_blocked == 0


def test_simulated_whole_flow_and_labeling(make_client, server):
    c = make_client()
    chunks = _chunks(c, 3)
    ctl = SimulatedContentControl(deny=[r"DROP"], mask=[r"\d{4}"])
    assert "NOT A SECURITY CONTROL" in (SimulatedContentControl.__doc__ or "")
    g = GuardedModelCall(c, P, "rag", input_control=ctl, output_control=ctl)
    seen = {}

    def create(*, messages):
        seen["m"] = [m["content"] for m in messages]
        return _resp("pin 1234")

    resp, receipt = g.wrap_openai_compatible(create)(messages=_msgs(chunks, ["x", "DROP me", "id 9999"]))
    assert seen["m"] == ["sys", "x", "id [MASKED]"]
    assert resp["choices"][0]["message"]["content"] == "pin [MASKED]"
    assert {a.provider for a in receipt.content_assessments} == {"simulated"}
    assert [a.action for a in receipt.content_assessments] == ["blocked", "masked", "masked"]
    env = server.envelopes[receipt.context_id]
    assert {x["context_id"] for x in env["parent_refs"]} == {
        chunks[0][1]["context_id"],
        chunks[2][1]["context_id"],
    }


def test_no_control_configured_sends_nothing_and_matches_baseline(make_client, server):
    c = make_client()
    chunks = _chunks(c, 2)
    g = GuardedModelCall(c, P, "rag")
    assert g.input_control is None and g.output_control is None
    p = g.prepare(_msgs(chunks, ["a", "b"]))
    assert p.content_assessments == [] and p.decision_summary.content_blocked == 0
    resp, receipt = g.wrap_openai_compatible(lambda **kw: _resp("raw 555-1234"))(
        messages=_msgs(chunks, ["a", "b"])
    )
    assert resp["choices"][0]["message"]["content"] == "raw 555-1234"
    assert receipt.content_assessments == []
    assert server.envelopes[receipt.context_id]["content_digest"] == digest("raw 555-1234")


def test_assessment_has_no_text_fields():
    a = ContentAssessment("masked", "sha256:x", "p", None, {}, masked_text="secret")
    assert "secret" not in repr(a) and a.redacted().masked_text is None
