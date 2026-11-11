import asyncio

import pytest
from ales_adapters.coverage import ADAPTER_COVERAGE
from ales_adapters.langgraph_middleware import guard_node, register_output
from ales_sdk import new_derivative, new_source
from conftest import PRINCIPAL


def _docs(client):
    srcs = [new_source("t1", f"d{i}", f"c{i}", "test") for i in range(2)]
    docs = []
    for s in srcs:
        client.register_source(s)
        d = new_derivative("chunk", [s], "t1", "chunk", "x")
        client.register_derivation(d)
        docs.append(d)
    return srcs, docs


def test_guard_node_filters_revoked_docs_and_taints_session(client):
    srcs, docs = _docs(client)
    client.submit_revocation({"source_id": srcs[0]["context_id"], "reason": "deleted"})

    @guard_node(client, PRINCIPAL, "support", lambda d: d["context_id"])
    def retrieve(state):
        return {"documents": list(docs), "other": 1}

    out = retrieve({"session_id": "s9"})
    assert out["documents"] == [docs[1]] and out["other"] == 1
    assert out["ales_blocked"][0]["context_id"] == docs[0]["context_id"]
    assert out["ales_blocked"][0]["decision"] == "DENY"
    assert client.session_taint.contexts_for("s9") == {docs[1]["context_id"]}


def test_guard_node_input_phase_and_results_key(client):
    srcs, docs = _docs(client)
    client.submit_revocation({"source_id": srcs[1]["context_id"], "reason": "deleted"})
    seen = {}

    @guard_node(client, PRINCIPAL, "support", lambda d: d["context_id"], phase="input")
    def node(state):
        seen.update(state)
        return {}

    out = node({"results": list(docs)})
    assert seen["results"] == [docs[0]]
    assert out["ales_blocked"][0]["key"] == "results"


def test_guard_node_async_and_bad_phase(client):
    _, docs = _docs(client)

    @guard_node(client, PRINCIPAL, "support", lambda d: d["context_id"])
    async def anode(state):
        return {"documents": list(docs)}

    assert asyncio.run(anode({}))["documents"] == docs
    with pytest.raises(ValueError):
        guard_node(client, PRINCIPAL, "p", lambda d: d, phase="x")


def test_register_output_registers_summary_with_parents(client, server):
    _, docs = _docs(client)

    @register_output(client, "documents", kind="summary")
    def summarize(state):
        return {"text": "the summary"}

    out = summarize({"documents": docs})
    env = server.envelopes[out["ales_context_id"]]
    assert env["kind"] == "summary"
    assert [p["context_id"] for p in env["parent_refs"]] == [d["context_id"] for d in docs]
    assert out["text"] == "the summary"


def test_registered_summary_dies_with_parent(client):
    srcs, docs = _docs(client)

    @register_output(client, "documents")
    def summarize(state):
        return {"text": "s"}

    out = summarize({"documents": docs})
    client.submit_revocation({"source_id": srcs[0]["context_id"], "reason": "deleted"})
    assert not client.authorize(PRINCIPAL, "support", [out["ales_context_id"]]).allowed


def test_register_output_noop_without_parents(client, server):
    @register_output(client, "documents")
    def summarize(state):
        return {"text": "s"}

    assert summarize({}) == {"text": "s"}
    assert not [r for r in server.requests if r[1] == "/v1/derivations"]


def test_coverage_declarations():
    assert set(ADAPTER_COVERAGE) == {"fs_source", "pgvector_store", "redis_cache", "langgraph_middleware"}
    for v in ADAPTER_COVERAGE.values():
        assert v["enforcement"] in ("ENFORCING", "OBSERVE_ONLY")
        assert {"enters", "derives", "retrieves", "can_block"} <= set(v)
    assert ADAPTER_COVERAGE["fs_source"]["can_block"].startswith("n/a")
