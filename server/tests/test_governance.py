"""v0.3 governance surface over HTTP: policies, approvals, workloads, delegations, handoffs, metrics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from ales_core import AuditLog
from ales_sdk import InvariantClient
from ales_sdk.errors import HandoffDenied
from ales_sdk.handoff import handoff as sdk_handoff
from fastapi.testclient import TestClient
from server_helpers import ALL, T2, TOKENS, P, TestClientTransport, authorize_body, bearer, chain
from sqlalchemy import select

ADMIN = bearer("tok-t1-admin")
READ = bearer("tok-t1-read")


def _register(client, tenant="t1", headers=None):
    src, chunk, summ = chain(tenant)
    for env in (src,):
        assert client.post("/v1/sources", json=env, headers=headers).status_code == 200
    for env in (chunk, summ):
        assert client.post("/v1/derivations", json=env, headers=headers).status_code == 200
    return summ["context_id"]


def _policy(rules, version=1, default="allow", policy_id="pol", **extra):
    return {"policy_id": policy_id, "version": version, "rules": rules, "default_action": default, **extra}


def _install(client, doc, headers=None):
    return client.post("/v1/policies", json=doc, headers=headers)


def _activate(client, policy_id="pol", version=1, headers=None):
    return client.post(f"/v1/policies/{policy_id}/versions/{version}/activate", headers=headers)


def _clock(client, offset: float = 0.0):
    client.app.state.clock = lambda: datetime.now(UTC) + timedelta(seconds=offset)


def _audit(client, tenant="t1", action=None):
    with client.app.state.session_factory() as s:
        stmt = select(AuditLog).where(AuditLog.tenant_id == tenant)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        return list(s.scalars(stmt.order_by(AuditLog.seq)))


def test_policy_install_activate_and_authorize_sees_version(client):
    cid = _register(client)
    base = client.post("/v1/authorize", json=authorize_body("t1", cid)).json()
    assert base["decision"] == "ALLOW" and "@" not in base["policy_version"]

    r = _install(client, _policy([]))
    assert r.status_code == 201
    assert r.json()["policy_version"] == "pol@1" and r.json()["active"] is False
    assert (
        client.post("/v1/authorize", json=authorize_body("t1", cid)).json()["policy_version"]
        == base["policy_version"]
    )

    assert _activate(client).json()["active"] is True
    ok = client.post("/v1/authorize", json=authorize_body("t1", cid)).json()
    assert ok["decision"] == "ALLOW" and ok["policy_version"] == "pol@1"


def test_policy_deny_rule_gives_policy_denied(client):
    cid = _register(client)
    _install(
        client, _policy([{"rule_id": "no-alice", "effect": "deny", "subjects": {"principals": ["alice"]}}])
    )
    _activate(client)
    body = client.post("/v1/authorize", json=authorize_body("t1", cid)).json()
    assert body["decision"] == "DENY" and "POLICY_DENIED" in body["reason"]
    bob = authorize_body("t1", cid) | {"principal": {"type": "user", "id": "bob"}}
    assert client.post("/v1/authorize", json=bob).json()["decision"] == "ALLOW"
    # the decision audit carries the matched rule id (identifiers only)
    rec = _audit(client, action="decision.authorize")[-2]
    assert rec.detail["policy"]["policy_rule_id"] == "no-alice"


def test_policy_install_validation_and_conflicts(client):
    assert _install(client, _policy([])).status_code == 201
    assert _install(client, _policy([])).status_code == 409  # same version again
    assert _install(client, _policy([], version=0)).status_code == 422
    assert _install(client, _policy([{"rule_id": "x", "effect": "nope"}], version=2)).status_code == 422
    assert _install(client, {"policy_id": "p@x", "version": 1}).status_code == 422
    assert _install(client, _policy([], version=2, bogus=1)).status_code == 422  # extra fields forbidden
    assert _activate(client, "pol", 9).status_code == 404
    assert _activate(client, "ghost", 1).status_code == 404
    assert client.get("/v1/policies/pol/versions/9").status_code == 404
    assert client.get("/v1/policies/pol/versions/abc").status_code == 422


def test_policy_tenant_and_author_are_forced_from_credential(client):
    r = _install(client, _policy([], tenant_id="t2", created_by="mallory"))
    assert r.status_code == 403  # explicit foreign tenant is a mismatch, like every other route
    r = _install(client, _policy([], created_by="mallory", created_at="2001-01-01T00:00:00Z"))
    assert r.status_code == 201 and r.json()["created_by"] == "svc-t1"
    assert r.json()["created_at"].startswith("20") and not r.json()["created_at"].startswith("2001")
    doc = client.get("/v1/policies/pol/versions/1").json()["document"]
    assert doc["tenant_id"] == "t1" and doc["created_by"] == "svc-t1"
    acts = _audit(client, action="policy.install")
    assert [a.actor for a in acts] == ["svc-t1"]


def test_policy_list_get_rollback(client):
    _install(client, _policy([], version=1))
    _install(client, _policy([{"rule_id": "d", "effect": "deny"}], version=2))
    _activate(client, version=2)
    lst = client.get("/v1/policies").json()["policies"]
    assert [(p["policy_version"], p["active"]) for p in lst] == [("pol@1", False), ("pol@2", True)]
    got = client.get("/v1/policies/pol/versions/2").json()
    assert got["active"] is True and got["document"]["rules"][0]["rule_id"] == "d"
    _activate(client, version=1)  # rollback is allowed
    assert [p["active"] for p in client.get("/v1/policies").json()["policies"]] == [True, False]
    assert [a.actor for a in _audit(client, action="policy.activate")] == ["svc-t1", "svc-t1"]


HR = [{"rule_id": "hr", "effect": "human_review", "subjects": {"principals": ["alice"]}}]


def _hr_setup(client):
    cid = _register(client)
    _install(client, _policy(HR))
    _activate(client)
    return cid


def test_human_review_approval_expiry_cycle(client):
    cid = _hr_setup(client)
    body = authorize_body("t1", cid)
    first = client.post("/v1/authorize", json=body).json()
    assert first["decision"] == "HUMAN_REVIEW" and "APPROVAL_PENDING" in first["reason"]
    assert first["policy_version"] == "pol@1"

    pending = client.get("/v1/approvals?state=pending").json()["approvals"]
    assert len(pending) == 1 and pending[0]["state"] == "pending"
    # an identical retry reuses the same pending approval
    assert client.post("/v1/authorize", json=body).json()["decision"] == "HUMAN_REVIEW"
    assert len(client.get("/v1/approvals").json()["approvals"]) == 1
    aid = pending[0]["approval_id"]
    assert "svc-t1" == _audit(client, action="approval.request")[0].actor

    d = client.post(f"/v1/approvals/{aid}/decide", json={"approve": True, "ttl_seconds": 300}, headers=ADMIN)
    assert d.status_code == 200 and d.json()["state"] == "approved" and d.json()["decided_by"] == "admin-t1"
    assert client.get("/v1/approvals").json()["approvals"] == []
    again = client.post(
        f"/v1/approvals/{aid}/decide", json={"approve": True, "ttl_seconds": 5}, headers=ADMIN
    )
    assert again.status_code == 409

    allowed = client.post("/v1/authorize", json=body).json()
    assert allowed["decision"] == "ALLOW" and allowed["reason"] == ["OK"]
    assert _audit(client, action="decision.authorize")[-1].detail["policy"]["approval_id"] == aid
    # a different purpose is a different fingerprint: not covered
    other = authorize_body("t1", cid, purpose="other")
    assert client.post("/v1/authorize", json=other).json()["decision"] == "HUMAN_REVIEW"

    _clock(client, 301)  # past the ttl
    again = client.post("/v1/authorize", json=body).json()
    assert again["decision"] == "HUMAN_REVIEW"
    view = client.get(f"/v1/approvals/{aid}").json()
    assert view["state"] == "approved" and view["effective_state"] == "expired"


def test_denied_approval_gives_approval_denied(client):
    cid = _hr_setup(client)
    body = authorize_body("t1", cid)
    client.post("/v1/authorize", json=body)
    aid = client.get("/v1/approvals").json()["approvals"][0]["approval_id"]
    denied = client.post(
        f"/v1/approvals/{aid}/decide", json={"approve": False, "ttl_seconds": 60}, headers=ADMIN
    )
    assert denied.status_code == 200
    out = client.post("/v1/authorize", json=body).json()
    assert out["decision"] == "DENY" and out["reason"] == ["APPROVAL_DENIED"]
    assert client.get("/v1/approvals").json()["approvals"] == []


@pytest.mark.parametrize(
    "body",
    [
        {"approve": True},
        {"approve": True, "ttl_seconds": 0},
        {"approve": True, "ttl_seconds": -5},
        {"approve": True, "ttl_seconds": 10**9},
        {"approve": "yes", "ttl_seconds": 60},
        {"approve": True, "ttl_seconds": 60, "decided_by": "mallory"},
    ],
)
def test_approval_decide_validation(client, body):
    cid = _hr_setup(client)
    client.post("/v1/authorize", json=authorize_body("t1", cid))
    aid = client.get("/v1/approvals").json()["approvals"][0]["approval_id"]
    assert client.post(f"/v1/approvals/{aid}/decide", json=body).status_code == 422
    assert client.get(f"/v1/approvals/{aid}").json()["state"] == "pending"


def test_approval_unknown_and_state_filter(client):
    assert (
        client.post("/v1/approvals/nope/decide", json={"approve": True, "ttl_seconds": 5}).status_code == 404
    )
    assert client.get("/v1/approvals/nope").status_code == 404
    assert client.get("/v1/approvals?state=approved").status_code == 422


def test_decide_actor_is_the_authenticated_subject(client):
    cid = _hr_setup(client)
    client.post("/v1/authorize", json=authorize_body("t1", cid))
    aid = client.get("/v1/approvals").json()["approvals"][0]["approval_id"]
    client.post(f"/v1/approvals/{aid}/decide", json={"approve": True, "ttl_seconds": 60}, headers=ADMIN)
    assert [a.actor for a in _audit(client, action="approval.decide")] == ["admin-t1"]
    assert client.get(f"/v1/approvals/{aid}", headers=READ).json()["decided_by"] == "admin-t1"


def _wl(client, wid="ag1", kind="agent", caps=("search",), headers=None):
    return client.post(
        "/v1/workloads",
        json={"workload_id": wid, "kind": kind, "display_name": wid.upper(), "capabilities": list(caps)},
        headers=headers,
    )


def test_workload_crud_and_validation(client):
    r = _wl(client)
    assert r.status_code == 201 and r.json()["status"] == "active" and r.json()["capabilities"] == ["search"]
    assert _wl(client).status_code == 409
    assert _wl(client, "x", kind="robot").status_code == 422
    assert (
        client.post(
            "/v1/workloads", json={"workload_id": "", "kind": "agent", "display_name": "d"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/v1/workloads", json={"workload_id": "z", "kind": "agent", "display_name": "d", "x": 1}
        ).status_code
        == 422
    )
    assert [w["workload_id"] for w in client.get("/v1/workloads", headers=READ).json()["workloads"]] == [
        "ag1"
    ]
    assert client.patch("/v1/workloads/ag1", json={}).status_code == 422
    assert client.patch("/v1/workloads/ag1", json={"status": "bogus"}).status_code == 422
    assert client.patch("/v1/workloads/ghost", json={"status": "suspended"}).status_code == 404
    p = client.patch("/v1/workloads/ag1", json={"status": "suspended", "capabilities": ["a", "b"]})
    assert (
        p.status_code == 200 and p.json()["status"] == "suspended" and p.json()["capabilities"] == ["a", "b"]
    )
    assert {a.actor for a in _audit(client)} >= {"svc-t1"}
    assert [a.actor for a in _audit(client, action="workload.status")] == ["svc-t1"]


def test_workload_gate_over_http(client):
    cid = _register(client)
    body = authorize_body("t1", cid) | {"agent_id": "ag1", "tools": ["search"]}
    # no workloads yet: opt-in gate is off
    assert client.post("/v1/authorize", json=body).json()["decision"] == "ALLOW"

    _wl(client, "ag1", caps=("search",))
    assert client.post("/v1/authorize", json=body).json()["decision"] == "ALLOW"
    unknown = body | {"agent_id": "ghost"}
    assert client.post("/v1/authorize", json=unknown).json()["reason"] == ["WORKLOAD_SUSPENDED"]

    client.patch("/v1/workloads/ag1", json={"status": "suspended"})
    out = client.post("/v1/authorize", json=body).json()
    assert out["decision"] == "DENY" and "WORKLOAD_SUSPENDED" in out["reason"]

    client.patch("/v1/workloads/ag1", json={"status": "active"})
    nope = body | {"tools": ["delete_all"]}
    out = client.post("/v1/authorize", json=nope).json()
    assert out["decision"] == "DENY" and "CAPABILITY_MISSING" in out["reason"]
    client.patch("/v1/workloads/ag1", json={"capabilities": ["tool:delete_all"]})
    assert client.post("/v1/authorize", json=nope).json()["decision"] == "ALLOW"


def test_authorize_rejects_bad_tools_and_risk(client):
    cid = _register(client)
    assert (
        client.post("/v1/authorize", json=authorize_body("t1", cid) | {"risk": "extreme"}).status_code == 422
    )
    assert (
        client.post("/v1/authorize", json=authorize_body("t1", cid) | {"tools": ["t" * 600]}).status_code
        == 422
    )
    ok = client.post("/v1/authorize", json=authorize_body("t1", cid) | {"risk": "high", "tools": ["t"]})
    assert ok.status_code == 200
    detail = _audit(client, action="decision.authorize")[-1].detail
    assert detail["risk"] == "high" and detail["tools"] == ["t"]


def _two_workloads(client):
    assert _wl(client, "a1").status_code == 201
    assert _wl(client, "b1").status_code == 201


def _hand(client, purpose="rag", frm="a1", to="b1", headers=None):
    return client.post(
        "/v1/handoffs", json={"from_workload": frm, "to_workload": to, "purpose": purpose}, headers=headers
    )


def test_delegation_crud(client):
    _two_workloads(client)
    assert (
        client.post("/v1/delegations", json={"from_workload": "a1", "to_workload": "ghost"}).status_code
        == 422
    )
    assert (
        client.post(
            "/v1/delegations", json={"from_workload": "a1", "to_workload": "b1", "purposes": []}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/v1/delegations", json={"from_workload": "a1", "to_workload": "b1", "extra": 1}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/v1/delegations",
            json={"from_workload": "a1", "to_workload": "b1", "expires_at": "2030-01-01T00:00:00"},
        ).status_code
        == 422
    )  # naive datetimes are refused
    r = client.post("/v1/delegations", json={"from_workload": "a1", "to_workload": "b1", "purposes": ["rag"]})
    assert r.status_code == 201 and r.json()["status"] == "active" and r.json()["purposes"] == ["rag"]
    did = r.json()["delegation_id"]
    assert len(client.get("/v1/delegations", headers=READ).json()["delegations"]) == 1
    assert client.get("/v1/delegations?from_workload=zzz").json()["delegations"] == []
    d = client.delete(f"/v1/delegations/{did}")
    assert d.status_code == 200 and d.json()["status"] == "revoked" and d.json()["delegation_id"] == did
    assert client.delete(f"/v1/delegations/{did}").status_code == 200  # idempotent
    assert client.delete("/v1/delegations/nope").status_code == 404
    assert [a.actor for a in _audit(client, action="delegation.create")] == ["svc-t1"]
    assert {a.actor for a in _audit(client, action="delegation.revoke")} == {"svc-t1"}


def test_handoff_matrix(client):
    _two_workloads(client)
    miss = _hand(client)
    assert miss.status_code == 200
    assert miss.json() == {"decision": "DENY", "reason": ["DELEGATION_MISSING"]}

    soon = (datetime.now(UTC) + timedelta(seconds=120)).isoformat()
    client.post(
        "/v1/delegations",
        json={"from_workload": "a1", "to_workload": "b1", "purposes": ["rag"], "expires_at": soon},
    )
    assert _hand(client).json() == {"decision": "ALLOW", "reason": ["OK"]}
    assert _hand(client, purpose="other").json()["reason"] == ["DELEGATION_MISSING"]  # purpose not covered
    assert _hand(client, frm="b1", to="a1").json()["reason"] == ["DELEGATION_MISSING"]  # direction matters

    _clock(client, 600)  # delegation expired
    assert _hand(client).json() == {"decision": "DENY", "reason": ["DELEGATION_MISSING"]}
    _clock(client, 0)

    # suspended workload
    client.patch("/v1/workloads/b1", json={"status": "suspended"})
    assert _hand(client).json() == {"decision": "DENY", "reason": ["WORKLOAD_SUSPENDED"]}
    client.patch("/v1/workloads/b1", json={"status": "active"})
    assert _hand(client).json()["decision"] == "ALLOW"

    # revoked
    did = client.get("/v1/delegations").json()["delegations"][0]["delegation_id"]
    client.delete(f"/v1/delegations/{did}")
    assert _hand(client).json() == {"decision": "DENY", "reason": ["DELEGATION_MISSING"]}
    # unknown workloads deny, never 404
    assert _hand(client, frm="ghost", to="phantom").json()["decision"] == "DENY"

    calls = _audit(client, action="handoff.authorize")
    assert len(calls) >= 8 and {c.actor for c in calls} == {"svc-t1"}
    assert calls[0].detail["decision"] == "DENY" and calls[0].detail["reason"] == ["DELEGATION_MISSING"]
    assert calls[1].detail["decision"] == "ALLOW"


def test_handoff_body_is_strict(client):
    assert client.post("/v1/handoffs", json={"from_workload": "a", "to_workload": "b"}).status_code == 422
    assert (
        client.post(
            "/v1/handoffs",
            json={"from_workload": "a", "to_workload": "b", "purpose": "p", "tenant_id": "t1"},
        ).status_code
        == 422
    )
    assert _hand(client, purpose="").status_code == 422


def test_handoff_read_role_suffices(client):
    _two_workloads(client)
    assert _hand(client, headers=READ).status_code == 200
    assert (
        client.post(
            "/v1/delegations", json={"from_workload": "a1", "to_workload": "b1"}, headers=READ
        ).status_code
        == 403
    )


def test_sdk_handoff_wire_compat(make_client):
    tokens = {**TOKENS, "tok-sdk": {"tenant_id": "sdk-t", "roles": ALL, "subject": "sdk-svc"}}
    tc = make_client(tokens=tokens)
    sdk_headers = bearer("tok-sdk")
    for wid in ("a1", "b1"):
        assert (
            tc.post(
                "/v1/workloads",
                json={"workload_id": wid, "kind": "agent", "display_name": wid},
                headers=sdk_headers,
            ).status_code
            == 201
        )
    with InvariantClient("http://testserver", "sdk-t", "tok-sdk", transport=TestClientTransport(tc)) as sdk:
        sdk.session_taint.record("sess-a", ["ctx-1", "ctx-2"], principal=P, purpose="rag")
        with pytest.raises(HandoffDenied) as exc:
            sdk_handoff(sdk, "sess-a", "sess-b", from_workload="a1", to_workload="b1", purpose="rag")
        assert "DELEGATION_MISSING" in str(exc.value.args) + str(exc.value)
        assert sdk.session_taint.contexts_for("sess-b") == set()  # nothing transferred on DENY

        assert (
            tc.post(
                "/v1/delegations",
                json={"from_workload": "a1", "to_workload": "b1", "purposes": ["rag"]},
                headers=sdk_headers,
            ).status_code
            == 201
        )
        res = sdk_handoff(sdk, "sess-a", "sess-b", from_workload="a1", to_workload="b1", purpose="rag")
        assert res.decision == "ALLOW" and res.reasons == ["OK"]
        assert sdk.session_taint.contexts_for("sess-b") == {"ctx-1", "ctx-2"}


def test_cross_tenant_isolation_of_new_resources(client):
    # tenant t1 builds state
    _install(client, _policy(HR))
    _activate(client)
    _wl(client, "ag1")
    _wl(client, "ag2")
    client.post("/v1/delegations", json={"from_workload": "ag1", "to_workload": "ag2"})
    did = client.get("/v1/delegations").json()["delegations"][0]["delegation_id"]
    cid = _register(client)
    client.post("/v1/authorize", json=authorize_body("t1", cid))
    aid = client.get("/v1/approvals").json()["approvals"][0]["approval_id"]

    assert client.get("/v1/policies", headers=T2).json() == {"policies": []}
    assert client.get("/v1/policies/pol/versions/1", headers=T2).status_code == 404
    assert _activate(client, headers=T2).status_code == 404
    assert client.get("/v1/workloads", headers=T2).json() == {"workloads": []}
    assert client.patch("/v1/workloads/ag1", json={"status": "suspended"}, headers=T2).status_code == 404
    assert client.get("/v1/delegations", headers=T2).json() == {"delegations": []}
    assert client.delete(f"/v1/delegations/{did}", headers=T2).status_code == 404
    assert client.get("/v1/approvals", headers=T2).json() == {"approvals": []}
    assert client.get(f"/v1/approvals/{aid}", headers=T2).status_code == 404
    assert (
        client.post(
            f"/v1/approvals/{aid}/decide", json={"approve": True, "ttl_seconds": 60}, headers=T2
        ).status_code
        == 404
    )
    # t2 handoffs do not see t1 delegations/workloads
    assert _hand(client, frm="ag1", to="ag2", headers=T2).json()["decision"] == "DENY"
    # ... and nothing of t1 changed
    assert client.get(f"/v1/approvals/{aid}").json()["state"] == "pending"
    assert client.get("/v1/delegations").json()["delegations"][0]["status"] == "active"
    assert client.get("/v1/workloads").json()["workloads"][0]["status"] == "active"
    # t2 policy of the same id is independent
    assert _install(client, _policy([]), headers=T2).status_code == 201
    assert [p["active"] for p in client.get("/v1/policies").json()["policies"]] == [True]
    # explicit foreign tenant in a body/query is a 403 as everywhere else
    assert client.post("/v1/policies", json=_policy([], version=5, tenant_id="t2")).status_code == 403
    assert client.get("/v1/approvals?tenant_id=t2").status_code == 403


def test_metrics_content_and_scoping(client):
    cid = _register(client)
    client.post("/v1/authorize", json=authorize_body("t1", cid))
    _install(client, _policy([]))
    _activate(client)
    client.post("/v1/authorize", json=authorize_body("t1", cid))
    r = client.get("/v1/metrics", headers=READ)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    txt = r.text
    assert "# TYPE ales_authorize_total counter" in txt
    assert 'ales_authorize_total{decision="ALLOW"} 2' in txt
    assert 'ales_outbox_rows{state="pending"}' in txt
    assert 'ales_policy_active_info{policy_id="pol",version="1"} 1' in txt
    assert "ales_audit_records_total " in txt and "ales_uptime_seconds " in txt
    assert "ales_revocations_total " in txt
    # another tenant sees only its own (zero) counters, and no policy
    other = client.get("/v1/metrics", headers=T2).text
    assert "decision=" not in other and "ales_policy_active_info" not in other


def test_metrics_counts_revocations(client):
    src = chain()[0]
    client.post("/v1/sources", json=src)
    assert (
        client.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"}).status_code
        == 200
    )
    assert "ales_revocations_total 1" in client.get("/v1/metrics").text


def test_metrics_requires_auth_by_default_and_public_flag(make_client):
    c = make_client()
    bare = TestClient(c.app)
    assert bare.get("/v1/metrics").status_code == 401
    assert bare.get("/v1/metrics", headers=bearer("tok-t1-ingest")).status_code == 403

    pub = make_client(env={"ALES_METRICS_PUBLIC": "1"})
    scrape = TestClient(pub.app)
    r = scrape.get("/v1/metrics")
    assert r.status_code == 200 and "ales_uptime_seconds" in r.text
    # exemption is for /metrics only
    assert scrape.get("/v1/workloads").status_code == 401
    assert scrape.get("/v1/outbox/stats").status_code == 401


ALICE_ADMIN = {"tok-alice-admin": {"tenant_id": "t1", "roles": ["admin"], "subject": "alice"}}
SOD = "separation of duties: decider matches requester"


def _pending_aid(client):
    cid = _hr_setup(client)
    client.post("/v1/authorize", json=authorize_body("t1", cid))  # token subject svc-t1, principal alice
    return client.get("/v1/approvals").json()["approvals"][0]["approval_id"]


@pytest.mark.parametrize("approve", [True, False])
def test_self_approval_blocked_for_both_identities(make_client, approve):
    client = make_client(tokens=TOKENS | ALICE_ADMIN)
    aid = _pending_aid(client)
    view = client.get(f"/v1/approvals/{aid}").json()
    assert (view["requested_by_principal"], view["requested_actor"]) == ("alice", "svc-t1")
    body = {"approve": approve, "ttl_seconds": 60}
    # the authenticated requester (token subject svc-t1 holds admin)
    r = client.post(f"/v1/approvals/{aid}/decide", json=body)
    assert r.status_code == 409 and r.json() == {"detail": SOD}
    # the principal whose access is pending (an admin whose subject is alice)
    r = client.post(f"/v1/approvals/{aid}/decide", json=body, headers=bearer("tok-alice-admin"))
    assert r.status_code == 409 and r.json() == {"detail": SOD}
    assert client.get(f"/v1/approvals/{aid}").json()["state"] == "pending"
    assert _audit(client, action="approval.decide") == []
    # a different admin may decide
    ok = client.post(f"/v1/approvals/{aid}/decide", json=body, headers=ADMIN)
    assert ok.status_code == 200 and ok.json()["decided_by"] == "admin-t1"


def test_approval_allow_self_escape_hatch(make_client):
    client = make_client(approval_allow_self=True)
    aid = _pending_aid(client)
    r = client.post(f"/v1/approvals/{aid}/decide", json={"approve": True, "ttl_seconds": 60})
    assert r.status_code == 200 and r.json()["decided_by"] == "svc-t1"
    env_client = make_client(env={"ALES_APPROVAL_ALLOW_SELF": "1"})
    aid = _pending_aid(env_client)
    assert (
        env_client.post(f"/v1/approvals/{aid}/decide", json={"approve": True, "ttl_seconds": 60}).status_code
        == 200
    )
    default = make_client(env={})
    assert default.app.state.settings.approval_allow_self is False


def test_grant_lifecycle_and_audit(client):
    _wl(client, "ag1")
    r = client.post("/v1/workloads/ag1/grants", json={"principal_id": "alice"}, headers=ADMIN)
    assert r.status_code == 201
    assert r.json()["principal_id"] == "alice" and r.json()["workload_id"] == "ag1"
    assert r.json()["granted_by"] == "admin-t1"
    again = client.post("/v1/workloads/ag1/grants", json={"principal_id": "alice"}, headers=ADMIN)
    assert again.status_code == 201  # idempotent
    client.post("/v1/workloads/ag1/grants", json={"principal_id": "bob"}, headers=ADMIN)
    assert [g["principal_id"] for g in client.get("/v1/grants", headers=READ).json()["grants"]] == [
        "alice",
        "bob",
    ]
    only_bob = client.get("/v1/grants?principal_id=bob", headers=READ).json()["grants"]
    assert [g["principal_id"] for g in only_bob] == ["bob"]
    assert client.get("/v1/grants?principal_id=zed", headers=READ).json() == {"grants": []}
    d = client.delete("/v1/workloads/ag1/grants/alice", headers=ADMIN)
    assert d.status_code == 200 and d.json()["revoked"] is True
    assert client.delete("/v1/workloads/ag1/grants/alice", headers=ADMIN).status_code == 404
    assert [(a.actor, a.detail["principal_id"]) for a in _audit(client, action="workload.grant")] == [
        ("admin-t1", "alice"),
        ("admin-t1", "bob"),
    ]
    assert [a.actor for a in _audit(client, action="workload.grant_revoke")] == ["admin-t1"]


def test_grant_validation_roles_and_unknowns(client):
    _wl(client, "ag1")
    assert (
        client.post("/v1/workloads/ghost/grants", json={"principal_id": "alice"}, headers=ADMIN).status_code
        == 404
    )
    for bad in ({}, {"principal_id": ""}, {"principal_id": "a", "x": 1}, {"principal_id": 5}):
        assert client.post("/v1/workloads/ag1/grants", json=bad, headers=ADMIN).status_code == 422, bad
    assert (
        client.post("/v1/workloads/ag1/grants", json={"principal_id": "a"}, headers=READ).status_code == 403
    )
    assert client.delete("/v1/workloads/ag1/grants/a", headers=READ).status_code == 403
    assert client.get("/v1/grants", headers=ADMIN).status_code == 403  # admin alone has no read role
    assert client.get("/v1/grants?tenant_id=t2").status_code == 403


def test_grant_cross_tenant_isolation(client):
    _wl(client, "ag1")
    client.post("/v1/workloads/ag1/grants", json={"principal_id": "alice"}, headers=ADMIN)
    assert client.get("/v1/grants", headers=T2).json() == {"grants": []}
    assert (
        client.post("/v1/workloads/ag1/grants", json={"principal_id": "alice"}, headers=T2).status_code == 404
    )
    assert client.delete("/v1/workloads/ag1/grants/alice", headers=T2).status_code == 404
    assert len(client.get("/v1/grants").json()["grants"]) == 1  # t1 untouched


def test_grants_gate_over_http(client):
    cid = _register(client)
    body = authorize_body("t1", cid) | {"agent_id": "ag1"}  # principal alice
    _wl(client, "ag1", caps=())
    assert client.post("/v1/authorize", json=body).json()["decision"] == "ALLOW"  # workloads but no grants
    client.post("/v1/workloads/ag1/grants", json={"principal_id": "bob"}, headers=ADMIN)
    out = client.post("/v1/authorize", json=body).json()
    assert out["decision"] == "DENY" and out["reason"] == ["PRINCIPAL_NOT_IN_SCOPE"]
    assert _audit(client, action="decision.authorize")[-1].detail["policy"]["grant_missing"] is True
    client.post("/v1/workloads/ag1/grants", json={"principal_id": "alice"}, headers=ADMIN)
    assert client.post("/v1/authorize", json=body).json()["decision"] == "ALLOW"
    # no agent_id: the grants gate does not apply
    assert client.post("/v1/authorize", json=authorize_body("t1", cid)).json()["decision"] == "ALLOW"
    client.delete("/v1/workloads/ag1/grants/alice", headers=ADMIN)  # revoked grant denies again
    assert client.post("/v1/authorize", json=body).json()["reason"] == ["PRINCIPAL_NOT_IN_SCOPE"]
    client.patch("/v1/workloads/ag1", json={"status": "suspended"})
    assert client.post("/v1/authorize", json=body).json()["reason"] == ["WORKLOAD_SUSPENDED"]


def test_enforce_workloads_config(make_client):
    from ales_server.config import ConfigError

    for mode in ("auto", "strict", "off"):
        assert make_client(enforce_workloads=mode).app.state.settings.enforce_workloads == mode
    assert make_client(env={}).app.state.settings.enforce_workloads == "auto"
    assert (
        make_client(env={"ALES_ENFORCE_WORKLOADS": " Strict "}).app.state.settings.enforce_workloads
        == "strict"
    )
    for bad in ("lax", "1", "true"):
        with pytest.raises(ConfigError):
            make_client(env={"ALES_ENFORCE_WORKLOADS": bad})


@pytest.mark.parametrize("mode", ["auto", "strict", "off"])
def test_enforce_workloads_modes(make_client, mode):
    c = make_client(env={"ALES_ENFORCE_WORKLOADS": mode})
    cid = _register(c)
    plain = authorize_body("t1", cid)
    ghost = plain | {"agent_id": "ghost"}
    assert c.post("/v1/authorize", json=plain).json()["decision"] == "ALLOW"  # no agent_id: never gated
    verdict = c.post("/v1/authorize", json=ghost).json()
    if mode == "strict":  # zero workloads registered, still enforced
        assert verdict["decision"] == "DENY" and verdict["reason"] == ["WORKLOAD_SUSPENDED"]
        assert _audit(c, action="decision.authorize")[-1].detail["policy"]["workload_enforcement"] == "strict"
    else:
        assert verdict["decision"] == "ALLOW"
    # once a workload exists: auto and strict enforce, off never does
    _wl(c, "ag1", caps=("search",))
    c.patch("/v1/workloads/ag1", json={"status": "suspended"})
    gated = c.post("/v1/authorize", json=plain | {"agent_id": "ag1", "tools": ["x"]}).json()
    assert (gated["decision"] == "DENY") is (mode != "off")


def test_enforce_off_logs_loud_warning(make_client, caplog):
    with caplog.at_level("WARNING", logger="ales.server"):
        make_client(enforce_workloads="off")
    assert any("ALES_ENFORCE_WORKLOADS=off" in r.message for r in caplog.records)


def test_risk_floors_over_http(client):
    cid = _register(client)
    rules = [{"rule_id": "no-high", "effect": "deny", "risk": "high"}]
    assert _install(client, _policy(rules, risk_floors={"rag": "high"})).status_code == 201
    _activate(client)
    for risk in (None, "low", "medium", "high"):
        body = authorize_body("t1", cid) | ({"risk": risk} if risk else {})
        out = client.post("/v1/authorize", json=body).json()
        assert out["decision"] == "DENY" and "POLICY_DENIED" in out["reason"], risk
    other = authorize_body("t1", cid, purpose="other") | {"risk": "low"}
    assert client.post("/v1/authorize", json=other).json()["decision"] == "ALLOW"
    assert client.get("/v1/policies/pol/versions/1").json()["document"]["risk_floors"] == {"rag": "high"}
    assert _install(client, _policy(rules, version=2, risk_floors={"rag": "extreme"})).status_code == 422
    assert _install(client, _policy(rules, version=3, risk_floors={"": "low"})).status_code == 422
