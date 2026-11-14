"""SDK durable sessions against a real server: restart survival, revocation flag, reset, handoff."""

from __future__ import annotations

from ales_sdk import InvariantClient
from ales_sdk.handoff import handoff
from ales_server import create_app
from fastapi.testclient import TestClient
from server_helpers import T1, TOKENS, P, TestClientTransport, chain


def sdk(tc, **kw):
    return InvariantClient(
        "http://testserver", "t1", auth_token="tok-t1-all", transport=TestClientTransport(tc), max_retries=0, **kw
    )


def test_exposures_survive_a_new_sdk_process_and_revocation_flags_the_session(tmp_path):
    url = f"sqlite:///{tmp_path / 'ales.db'}"
    kw = {"tokens": TOKENS, "outbox_interval": 0}
    with TestClient(create_app(url, **kw), headers=T1) as tc:
        src, chunk, summ = chain("t1")
        c = sdk(tc, durable_sessions=True)
        c.register_source(src)
        c.register_derivation(chunk)
        c.register_derivation(summ)
        c.session_taint.record("run-1", [(summ["context_id"], summ["object_version"])], principal=P, purpose="rag")
        assert c.session_exposures("run-1")["exposure_count"] == 1
    # "new process": fresh server app AND fresh SDK client with an empty in-memory taint
    with TestClient(create_app(url, **kw), headers=T1) as tc2:
        c2 = sdk(tc2)
        assert c2.session_taint.contexts_for("run-1") == set()  # the local record died with the old process
        view = c2.session_exposures("run-1")
        assert (view["exposure_count"], view["needs_reset"]) == (1, False)
        c2.submit_revocation({"source_id": src["context_id"], "reason": "acl_changed"})
        flagged = c2.session_exposures("run-1")
        assert flagged["needs_reset"] is True
        reset = c2.reset_session("run-1")
        assert (reset["generation"], reset["needs_reset"]) == (1, False)
        assert c2.session_exposures("run-1")["exposure_count"] == 0


def test_handoff_records_the_receiver_session_server_side(client):
    src, chunk, summ = chain("t1")
    c = sdk(client, durable_sessions=True)
    for env, fn in ((src, c.register_source), (chunk, c.register_derivation), (summ, c.register_derivation)):
        fn(env)
    client.post("/v1/workloads", json={"workload_id": "a", "kind": "agent", "display_name": "A"}, headers=T1)
    client.post("/v1/workloads", json={"workload_id": "b", "kind": "agent", "display_name": "B"}, headers=T1)
    client.post("/v1/delegations", json={"from_workload": "a", "to_workload": "b"}, headers=T1)
    c.session_taint.record("sender", [(summ["context_id"], summ["object_version"])], principal=P, purpose="rag")
    res = handoff(c, "sender", "receiver", from_workload="a", to_workload="b", purpose="rag")
    assert res.decision == "ALLOW"
    assert c.session_exposures("receiver")["exposure_count"] == 1
    imp = client.get(f"/v1/impact/{src['context_id']}").json()
    assert imp["exposed_sessions"]["ids"] == ["receiver", "sender"]
