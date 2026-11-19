"""External policy providers + release gate (v0.4), end to end against a fake OPA over real HTTP."""

from __future__ import annotations

import json
import socket
import uuid
from datetime import UTC, datetime

import pytest
from ales_core import AuditLog, ReleaseReceiptRow, RevocationEngine, RevocationEvent
from ales_sdk import HumanReviewPending, InvariantClient, ReleaseDenied
from ales_server.config import ConfigError
from ales_server.providers import parse_providers
from fake_opa import FakeOPA
from server_helpers import P, TestClientTransport, authorize_body, chain
from sqlalchemy import select


@pytest.fixture
def opa():
    o = FakeOPA()
    yield o
    o.stop()


def dead_url() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}/v1/data/x"


def prov(url, **kw):
    return {"name": kw.pop("name", "opa1"), "url": url, "kind": kw.pop("kind", "opa"), **kw}


@pytest.fixture
def mk(make_client):
    def _mk(*provs, env=None, **kw):
        e = {"ALES_POLICY_PROVIDERS": json.dumps(list(provs)), **(env or {})}
        return make_client(env=e, **kw)

    return _mk


def seed(c):
    src, chunk, summ = chain("t1")
    assert c.post("/v1/sources", json=src).status_code == 200
    assert c.post("/v1/derivations", json=chunk).status_code == 200
    assert c.post("/v1/derivations", json=summ).status_code == 200
    return src, chunk, summ


def audits(c, action):
    with c.app.state.session_factory() as s:
        return [
            a.detail
            for a in s.scalars(
                select(AuditLog)
                .where(AuditLog.tenant_id == "t1", AuditLog.action == action)
                .order_by(AuditLog.seq)
            )
        ]


def authz(c, cid):
    return c.post("/v1/authorize", json=authorize_body("t1", cid)).json()


def rel_body(cid, action="send_email", destination="mail:acme.com", **kw):
    return {
        "principal": P,
        "action": action,
        "destination": destination,
        "purpose": "outreach",
        "objects": [{"context_id": cid}],
        **kw,
    }


def test_no_providers_unchanged(client):
    _, _, summ = seed(client)
    r = authz(client, summ["context_id"])
    assert r["decision"] == "ALLOW"
    assert "external" not in audits(client, "decision.authorize")[-1]["policy"]


def test_required_opa_deny(mk, opa):
    opa.policy = lambda i: False
    c = mk(prov(opa.url))
    _, _, summ = seed(c)
    r = authz(c, summ["context_id"])
    assert r["decision"] == "DENY" and r["reason"] == ["EXTERNAL_POLICY_DENIED"]
    ext = audits(c, "decision.authorize")[-1]["policy"]["external"]
    rec = ext["providers"][0]
    assert rec["name"] == "opa1" and rec["decision"] == "DENY" and rec["policy_revision"] == "unversioned"
    assert isinstance(rec["latency_ms"], int) and rec["required"] is True


def test_opa_input_carries_verified_facts(mk, opa):
    c = mk(prov(opa.url))
    _, _, summ = seed(c)
    authz(c, summ["context_id"])
    call = opa.calls[-1]
    inp = call["body"]["input"]
    assert inp["action"] == "context.use" and inp["principal"] == P and inp["purpose"] == "rag"
    assert inp["resource_refs"][0]["classification"] == "confidential"
    assert inp["verified_context"]["ales_decision"] == "ALLOW"


def test_optional_down_allows_and_records(mk):
    c = mk(prov(dead_url(), required=False))
    _, _, summ = seed(c)
    assert authz(c, summ["context_id"])["decision"] == "ALLOW"
    rec = audits(c, "decision.authorize")[-1]["policy"]["external"]["providers"][0]
    assert rec["status"] == "unavailable" and rec["required"] is False and rec["error"] == "connect"


def test_required_down_is_unknown(mk):
    c = mk(prov(dead_url(), required=True))
    _, _, summ = seed(c)
    r = authz(c, summ["context_id"])
    assert r["decision"] == "UNKNOWN" and r["reason"] == ["EXTERNAL_POLICY_UNAVAILABLE"]


def test_obligations_and_object_result_form_in_audit(mk, opa):
    opa.policy = lambda i: {
        "allow": True,
        "obligations": ["mask:email", {"max_rows": 5}],
        "policy_revision": "rev-9",
    }
    c = mk(prov(opa.url))
    _, _, summ = seed(c)
    assert authz(c, summ["context_id"])["decision"] == "ALLOW"
    ext = audits(c, "decision.authorize")[-1]["policy"]["external"]
    assert ext["providers"][0]["policy_revision"] == "rev-9"
    assert "mask:email" in ext["obligations"][0] and "max_rows" in ext["obligations"][1]


def test_opa_full_decision_object_and_human_review_creates_approval(mk, opa):
    opa.policy = lambda i: {"decision": "HUMAN_REVIEW", "policy_revision": "r3"}
    c = mk(prov(opa.url))
    _, _, summ = seed(c)
    r = authz(c, summ["context_id"])
    assert r["decision"] == "HUMAN_REVIEW" and "APPROVAL_PENDING" in r["reason"]
    pend = c.get("/v1/approvals?state=pending").json()["approvals"]
    assert len(pend) == 1 and pend[0]["context"]["external"] == ["opa1@r3"]


@pytest.mark.parametrize(
    "result", [None, "allow", 7, {"nothing": 1}, {"decision": "allow"}, {"allow": "yes"}]
)
def test_malformed_opa_results_are_unavailable_never_allow(mk, opa, result):
    opa.raw = lambda b: (200, json.dumps({} if result is None else {"result": result}).encode(), {})
    c = mk(prov(opa.url))
    _, _, summ = seed(c)
    r = authz(c, summ["context_id"])
    assert r["decision"] == "UNKNOWN" and r["reason"] == ["EXTERNAL_POLICY_UNAVAILABLE"]


@pytest.mark.parametrize(
    "raw",
    [
        lambda b: (500, b"{}", {}),
        lambda b: (200, b"not json", {}),
        lambda b: (302, b"{}", {"Location": "http://127.0.0.1:1/x"}),
        lambda b: (200, b'{"result": true, "pad": "' + b"x" * 300_000 + b'"}', {}),
    ],
)
def test_transport_failures_fail_closed(mk, opa, raw):
    opa.raw = raw
    c = mk(prov(opa.url))
    _, _, summ = seed(c)
    assert authz(c, summ["context_id"])["decision"] == "UNKNOWN"


def test_timeout_is_unavailable(mk, opa):
    opa.delay = 1.5
    c = mk(prov(opa.url, timeout_s=0.3))
    _, _, summ = seed(c)
    r = authz(c, summ["context_id"])
    assert r["decision"] == "UNKNOWN"
    assert audits(c, "decision.authorize")[-1]["policy"]["external"]["providers"][0]["error"] == "timeout"


def test_bearer_token_from_env_ref(mk, opa):
    c = mk(prov(opa.url, auth_token_env="OPA_TOK"), env={"OPA_TOK": "s3cret"})
    _, _, summ = seed(c)
    authz(c, summ["context_id"])
    assert opa.calls[-1]["headers"]["Authorization"] == "Bearer s3cret"
    assert "s3cret" not in json.dumps(audits(c, "decision.authorize"))


def test_policy_path_is_appended(mk, opa):
    base = opa.url.split("/v1/")[0]
    c = mk(prov(base, policy_path="ales/release/allow"))
    _, _, summ = seed(c)
    authz(c, summ["context_id"])
    assert opa.calls[-1]["path"] == "/v1/data/ales/release/allow"


def test_providers_skipped_when_lineage_already_denies(mk, opa):
    c = mk(prov(opa.url))
    src, _, summ = seed(c)
    c.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "acl_changed"})
    n = len(opa.calls)
    r = authz(c, summ["context_id"])
    assert r["decision"] == "DENY" and "ANCESTOR_ACL_REVOKED" in r["reason"]
    assert len(opa.calls) == n
    assert audits(c, "decision.authorize")[-1]["policy"]["external"] == {"skipped": "base_decision_DENY"}


def test_provider_allow_never_loosens_lineage_deny(mk, opa):
    opa.policy = lambda i: True
    c = mk(prov(opa.url))
    src, _, summ = seed(c)
    c.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"})
    assert authz(c, summ["context_id"])["decision"] == "DENY"


def test_revocation_during_provider_call_is_revalidated(mk, opa):
    c = mk(prov(opa.url))
    src, _, summ = seed(c)

    def revoke_mid_call():
        opa.on_call = None
        with c.app.state.session_factory() as s:
            ev = RevocationEvent.model_validate(
                {
                    "event_id": str(uuid.uuid4()),
                    "tenant_id": "t1",
                    "source_id": src["context_id"],
                    "reason": "acl_changed",
                    "effective_at": datetime.now(UTC).isoformat(),
                }
            )
            RevocationEngine().accept(s, ev, actor="x")

    opa.on_call = revoke_mid_call
    r = authz(c, summ["context_id"])
    assert r["decision"] == "DENY" and "ANCESTOR_ACL_REVOKED" in r["reason"]
    assert audits(c, "decision.authorize")[-1]["policy"]["external"]["revalidated"] is True


def test_custom_kind_verbatim_shapes(mk, opa):
    opa.raw = lambda b: (
        200,
        json.dumps(
            {"decision": "DENY", "provider": "svc", "policy_revision": "v7", "explanation_ref": "trace-1"}
        ).encode(),
        {},
    )
    c = mk(prov(opa.url, kind="custom"))
    _, _, summ = seed(c)
    r = authz(c, summ["context_id"])
    assert r["reason"] == ["EXTERNAL_POLICY_DENIED"]
    assert set(opa.calls[-1]["body"]) >= {
        "principal",
        "action",
        "resource_refs",
        "purpose",
        "verified_context",
    }
    assert (
        audits(c, "decision.authorize")[-1]["policy"]["external"]["providers"][0]["explanation_ref"]
        == "trace-1"
    )


def test_cedar_kind_maps_fields_and_requires_all_resources_allowed(mk, opa):
    opa.raw = lambda b: (
        200,
        json.dumps({"decision": "Deny" if "chunk" in b["resource"] else "Allow"}).encode(),
        {},
    )
    c = mk(prov(opa.url, kind="cedar"))
    _, _, summ = seed(c)
    r = authz(c, summ["context_id"])
    assert r["decision"] == "ALLOW"
    body = opa.calls[-1]["body"]
    assert body["principal"] == 'User::"alice"' and body["action"] == 'Action::"context.use"'
    assert body["resource"].startswith('Context::"') and body["context"]["purpose"] == "rag"
    opa.raw = lambda b: (200, json.dumps({"decision": "Deny"}).encode(), {})
    assert authz(c, summ["context_id"])["decision"] == "DENY"


def test_multiple_providers_composed(mk, opa):
    o2 = FakeOPA(lambda i: False)
    try:
        c = mk(
            prov(opa.url, name="a"),
            prov(o2.url, name="b", required=False),
            prov(dead_url(), name="c", required=False),
        )
        _, _, summ = seed(c)
        r = authz(c, summ["context_id"])
        assert r["decision"] == "DENY" and r["reason"] == ["EXTERNAL_POLICY_DENIED"]
        names = {
            p["name"]: p["status"]
            for p in audits(c, "decision.authorize")[-1]["policy"]["external"]["providers"]
        }
        assert names == {"a": "ok", "b": "ok", "c": "unavailable"}
    finally:
        o2.stop()


def test_parse_providers_errors():
    for raw in [
        "{",
        "{}",
        '[{"name":"a"}]',
        '[{"name":"a","url":"https://x","token":"inline"}]',
        '[{"name":"a","url":"https://x"},{"name":"a","url":"https://y"}]',
        '[{"name":"a","url":"https://x","auth_token_env":"NOPE_UNSET"}]',
    ]:
        with pytest.raises(ConfigError):
            parse_providers(raw, env={})
    assert parse_providers("", env={}) == ()
    with pytest.raises(ConfigError):
        parse_providers('[{"name":"a","url":"http://opa.internal/x"}]', production=True, env={})
    with pytest.raises(ConfigError):
        parse_providers('[{"name":"a","url":"https://opa.internal/x"}]', production=True, env={})
    ok = parse_providers(
        '[{"name":"a","url":"https://opa.internal/x","auth_token_env":"T"}]', production=True, env={"T": "v"}
    )
    assert ok[0].required is True


def test_bad_env_fails_startup(make_client):
    with pytest.raises(ConfigError):
        make_client(env={"ALES_POLICY_PROVIDERS": "nope"})


def test_release_allow_receipt_and_storage(client):
    _, _, summ = seed(client)
    r = client.post("/v1/releases", json=rel_body(summ["context_id"]))
    assert r.status_code == 200
    rc = r.json()
    uuid.UUID(rc["receipt_id"])
    assert rc["decision"] == "ALLOW" and rc["reason"] == ["OK"] and rc["policy_version"] == "p0"
    assert set(rc) == {
        "receipt_id",
        "decision",
        "reason",
        "valid_until",
        "revocation_epoch",
        "policy_version",
    }
    ttl = (datetime.fromisoformat(rc["valid_until"]) - datetime.now(UTC)).total_seconds()
    assert 0 < ttl <= 31
    with client.app.state.session_factory() as s:
        row = s.get(ReleaseReceiptRow, rc["receipt_id"])
        assert row is not None and row.decision == "ALLOW" and len(row.request_fingerprint) == 64
    d = audits(client, "release.authorize")[-1]
    assert (
        d["receipt_id"] == rc["receipt_id"]
        and d["action"] == "send_email"
        and d["destination"] == "mail:acme.com"
    )


def test_release_revoked_object_denied_with_ancestor_reason(client):
    src, _, summ = seed(client)
    client.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "acl_changed"})
    rc = client.post("/v1/releases", json=rel_body(summ["context_id"])).json()
    assert rc["decision"] == "DENY"
    assert rc["reason"][0] == "RELEASE_DENIED" and "ANCESTOR_ACL_REVOKED" in rc["reason"]
    assert datetime.fromisoformat(rc["valid_until"]) <= datetime.now(UTC)


def test_release_unknown_object_and_validation(client):
    rc = client.post("/v1/releases", json=rel_body("nope")).json()
    assert rc["decision"] == "UNKNOWN" and rc["reason"][0] == "RELEASE_DENIED"
    assert client.post("/v1/releases", json={**rel_body("x"), "extra": 1}).status_code == 422
    assert client.post("/v1/releases", json={**rel_body("x"), "objects": []}).status_code == 422
    assert client.post("/v1/releases", json={**rel_body("x"), "tenant_id": "t2"}).status_code == 403


def test_release_needs_read_role(client):
    h = {"Authorization": "Bearer tok-t1-ingest"}
    assert client.post("/v1/releases", json=rel_body("x"), headers=h).status_code == 403


def test_release_passes_action_and_destination_to_provider(mk, opa):
    opa.policy = lambda i: not i["destination"].endswith("external.com")
    c = mk(prov(opa.url))
    _, _, summ = seed(c)
    ok = c.post("/v1/releases", json=rel_body(summ["context_id"], destination="mail:corp.com")).json()
    bad = c.post("/v1/releases", json=rel_body(summ["context_id"], destination="mail:x@external.com")).json()
    assert ok["decision"] == "ALLOW"
    assert bad["decision"] == "DENY" and bad["reason"] == ["RELEASE_DENIED", "EXTERNAL_POLICY_DENIED"]
    inp = opa.calls[-1]["body"]["input"]
    assert inp["action"] == "send_email" and inp["destination"] == "mail:x@external.com"
    assert audits(c, "release.authorize")[-1]["policy"]["external"]["providers"][0]["decision"] == "DENY"


def test_release_valid_until_bounded_by_provider(mk, opa):
    opa.policy = lambda i: {"allow": True, "valid_until": "2099-01-01T00:00:00Z"}
    c = mk(prov(opa.url))
    _, _, summ = seed(c)
    rc = c.post("/v1/releases", json=rel_body(summ["context_id"])).json()
    assert (datetime.fromisoformat(rc["valid_until"]) - datetime.now(UTC)).total_seconds() <= 31  # TTL wins
    soon = datetime.now(UTC).timestamp() + 5
    opa.policy = lambda i: {"allow": True, "valid_until": datetime.fromtimestamp(soon, UTC).isoformat()}
    rc = c.post("/v1/releases", json=rel_body(summ["context_id"])).json()
    assert (datetime.fromisoformat(rc["valid_until"]) - datetime.now(UTC)).total_seconds() <= 5.5


def test_release_workload_capability_and_suspension(client):
    _, _, summ = seed(client)
    w = {"workload_id": "mailer", "kind": "agent", "display_name": "m", "capabilities": ["action:send_email"]}
    assert client.post("/v1/workloads", json=w).status_code == 201
    cid = summ["context_id"]
    assert client.post("/v1/releases", json=rel_body(cid, workload="mailer")).json()["decision"] == "ALLOW"
    cap = client.post("/v1/releases", json=rel_body(cid, workload="mailer", action="delete_all")).json()
    assert cap["decision"] == "DENY" and "CAPABILITY_MISSING" in cap["reason"]
    client.patch("/v1/workloads/mailer", json={"status": "suspended"})
    sus = client.post("/v1/releases", json=rel_body(cid, workload="mailer")).json()
    assert "WORKLOAD_SUSPENDED" in sus["reason"]
    # no handoff/delegation gating on the release gate: no delegation exists and the first call still allowed
    assert client.post("/v1/releases", json=rel_body(cid)).json()["decision"] == "ALLOW"


def test_release_human_review_from_provider_creates_approval(mk, opa):
    opa.policy = lambda i: {"decision": "HUMAN_REVIEW", "policy_revision": "r1"}
    c = mk(prov(opa.url))
    _, _, summ = seed(c)
    rc = c.post("/v1/releases", json=rel_body(summ["context_id"])).json()
    assert rc["decision"] == "HUMAN_REVIEW" and rc["reason"][0] == "RELEASE_DENIED"
    ap = c.get("/v1/approvals?state=pending").json()["approvals"]
    assert ap and ap[0]["context"]["destination"] == "mail:acme.com"


def sdk(c, **kw):
    return InvariantClient(
        "http://testserver",
        "t1",
        auth_token="tok-t1-all",
        transport=TestClientTransport(c),
        max_retries=0,
        **kw,
    )


def test_sdk_release_destination_sensitive_opa_end_to_end(mk, opa):
    opa.policy = lambda i: not i["destination"].endswith("external.com")
    c = mk(prov(opa.url))
    _, _, summ = seed(c)
    cl = sdk(c)
    rc = cl.authorize_release(P, "send_email", "mail:corp.com", "outreach", [summ["context_id"]])
    assert rc.allowed and rc.receipt_id
    with pytest.raises(ReleaseDenied) as ei:
        cl.authorize_release(P, "send_email", "mail:a@external.com", "outreach", [summ["context_id"]])
    assert ei.value.reasons == ["RELEASE_DENIED", "EXTERNAL_POLICY_DENIED"]
    assert ei.value.receipt.decision == "DENY"
    # OBSERVE does not raise
    obs = sdk(c, fail_mode="OBSERVE").authorize_release(
        P, "send_email", "mail:a@external.com", "p", [summ["context_id"]]
    )
    assert obs.decision == "DENY"


def test_sdk_release_revoked_and_review(mk, opa):
    c = mk(prov(opa.url))
    src, _, summ = seed(c)
    cl = sdk(c)
    c.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"})
    with pytest.raises(ReleaseDenied) as ei:
        cl.authorize_release(P, "send_email", "d", "p", [summ["context_id"]])
    assert "ANCESTOR_DELETED" in ei.value.reasons


def test_sdk_release_human_review_and_unreachable(mk, opa):
    opa.policy = lambda i: {"decision": "HUMAN_REVIEW", "policy_revision": "x"}
    c = mk(prov(opa.url))
    _, _, summ = seed(c)
    with pytest.raises(HumanReviewPending):
        sdk(c).authorize_release(P, "send_email", "d", "p", [summ["context_id"]])
    tr = TestClientTransport(c)
    tr.down = True
    cl = InvariantClient("http://testserver", "t1", auth_token="tok-t1-all", transport=tr, max_retries=0)
    with pytest.raises(ReleaseDenied) as ei:
        cl.authorize_release(P, "send_email", "d", "p", [summ["context_id"]])
    assert ei.value.receipt.synthesised and "RELEASE_SERVER_UNAVAILABLE" in ei.value.reasons
