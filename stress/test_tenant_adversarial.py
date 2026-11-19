"""Adversarial tenant-isolation and privilege suite (runs on SQLite and, with TEST_POSTGRES_URL, Postgres).

Two tenants share one server and one database. Tenant ``t2`` (full roles) attacks every resource that
belongs to ``t1``; each probe must be indistinguishable from a probe for something that does not exist
(and must not change t1's state). A read-only ``t1`` credential then walks the whole OpenAPI route table:
nothing outside the read role may succeed.

NOTE: application-level isolation only (see docs/residual-risks.md R31). Nothing here tests, or claims,
database-level isolation.
"""

from __future__ import annotations

import re
import uuid

import pytest
from ales_server import create_app
from fastapi.testclient import TestClient
from stress_helpers import PRINCIPAL, register_chain

ALL = ["ingest", "revoke", "read", "admin"]
TOKENS = {
    "a1": {"tenant_id": "t1", "roles": ALL, "subject": "svc-t1"},
    "a1-admin": {"tenant_id": "t1", "roles": ["admin"], "subject": "admin-t1"},
    "a1-read": {"tenant_id": "t1", "roles": ["read"], "subject": "reader-t1"},
    "a2": {"tenant_id": "t2", "roles": ALL, "subject": "svc-t2"},
}
HR = [{"rule_id": "hr", "effect": "human_review", "subjects": {"principals": ["alice"]}}]


def _h(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture
def world(db_url):
    app = create_app(db_url, tokens=TOKENS, outbox_interval=0)
    t1 = TestClient(app, headers=_h("a1"))
    t2 = TestClient(app, headers=_h("a2"))
    chain1 = register_chain(t1, "t1")
    chain2 = register_chain(t2, "t2")
    # t1 governance state: policy (human-review), workload, grant, delegation, one pending approval
    pol = {"policy_id": "pol", "version": 1, "rules": HR, "default_action": "allow"}
    assert t1.post("/v1/policies", json=pol).status_code == 201
    assert t1.post("/v1/policies/pol/versions/1/activate").status_code == 200
    for wid in ("w-a", "w-b"):
        body = {"workload_id": wid, "kind": "agent", "display_name": wid, "capabilities": []}
        assert t1.post("/v1/workloads", json=body).status_code == 201
    assert t1.post("/v1/workloads/w-a/grants", json={"principal_id": "alice"}).status_code == 201
    d = t1.post("/v1/delegations", json={"from_workload": "w-a", "to_workload": "w-b"})
    assert d.status_code == 201
    mem1 = chain1[3]["context_id"]
    r = t1.post("/v1/authorize", json=_auth("t1", mem1))
    assert r.json()["decision"] == "HUMAN_REVIEW"
    approval_id = t1.get("/v1/approvals", headers=_h("a1-admin")).json()["approvals"][0]["approval_id"]
    with t1, t2:
        t1_epoch = t1.post("/v1/authorize", json=_auth("t1", chain1[0]["context_id"])).json()[
            "revocation_epoch"
        ]
        yield {
            "app": app,
            "t1": t1,
            "t2": t2,
            "chain1": chain1,
            "chain2": chain2,
            "t1_epoch_baseline": t1_epoch,
            "delegation_id": d.json()["delegation_id"],
            "approval_id": approval_id,
        }


def _auth(tenant: str, cid: str) -> dict:
    return {"tenant_id": tenant, "principal": PRINCIPAL, "purpose": "rag", "objects": [{"context_id": cid}]}


def test_object_read_is_indistinguishable_from_unknown(world):
    t2 = world["t2"]
    foreign = t2.post("/v1/authorize", json=_auth("t2", world["chain1"][3]["context_id"]))
    unknown = t2.post("/v1/authorize", json=_auth("t2", str(uuid.uuid4())))
    assert foreign.status_code == unknown.status_code == 200
    f, u = foreign.json(), unknown.json()
    assert f["decision"] == "UNKNOWN" and f["reason"] == ["OBJECT_UNKNOWN"]
    assert "TENANT_MISMATCH" not in foreign.text
    for d in (f, u):
        d.pop("trace_id")
        d["objects"][0].pop("context_id")
    assert f == u
    # every node of t1's lineage looks the same, and a versioned probe too
    for env in world["chain1"]:
        r = t2.post("/v1/authorize", json=_auth("t2", env["context_id"])).json()
        assert r["decision"] == "UNKNOWN" and r["reason"] == ["OBJECT_UNKNOWN"]
    body = _auth("t2", world["chain1"][0]["context_id"])
    body["objects"][0]["version"] = world["chain1"][0]["object_version"]
    assert t2.post("/v1/authorize", json=body).json()["reason"] == ["OBJECT_UNKNOWN"]


def test_tenant_mismatch_only_in_t2_audit_detail(world):
    t2 = world["t2"]
    t2.post("/v1/authorize", json=_auth("t2", world["chain1"][3]["context_id"]))
    from ales_core.db import AuditLog
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    with Session(world["app"].state.engine) as s:
        rows = s.scalars(
            select(AuditLog).where(AuditLog.action == "decision.authorize", AuditLog.tenant_id == "t2")
        ).all()
        flagged = [
            r
            for r in rows
            if r.detail.get("policy", {}).get("tenant_mismatch") or r.detail.get("tenant_mismatch")
        ]
        assert flagged, [r.detail for r in rows]
        t1_rows = s.scalars(select(AuditLog).where(AuditLog.tenant_id == "t1")).all()
        assert not any("tenant_mismatch" in str(r.detail) for r in t1_rows)


def test_lineage_404_same_as_unknown(world):
    t2 = world["t2"]
    foreign = t2.get(f"/v1/lineage/{world['chain1'][0]['context_id']}")
    unknown = t2.get(f"/v1/lineage/{uuid.uuid4()}")
    assert foreign.status_code == unknown.status_code == 404
    strip = lambda r: re.sub(r"[0-9a-f-]{36}", "ID", r.text)
    assert strip(foreign) == strip(unknown)
    assert (
        t2.get(f"/v1/lineage/{world['chain1'][0]['context_id']}", params={"tenant_id": "t1"}).status_code
        == 403
    )


def test_revocation_by_other_tenant_is_a_noop(world):
    t1, t2 = world["t1"], world["t2"]
    src = world["chain1"][0]["context_id"]
    body = {
        "event_id": str(uuid.uuid4()),
        "tenant_id": "t2",
        "source_id": src,
        "reason": "deleted",
        "effective_at": "2020-01-01T00:00:00+00:00",
    }
    t2.post("/v1/revocations", json=body)  # accepted or rejected: either way it must not touch t1
    spoof = dict(body, event_id=str(uuid.uuid4()), tenant_id="t1")
    assert t2.post("/v1/revocations", json=spoof).status_code == 403
    for env in world["chain1"]:
        out = t1.post("/v1/authorize", json=_auth("t1", env["context_id"])).json()
        assert out["decision"] != "DENY" and "ANCESTOR_DELETED" not in out["reason"], out
    # t1 epoch untouched by t2's event (its baseline is nonzero: policy activation bumps it)
    before = world["t1_epoch_baseline"]
    assert t1.post("/v1/authorize", json=_auth("t1", src)).json()["revocation_epoch"] == before


def test_approval_endpoints_404_across_tenants(world):
    t2, aid = world["t2"], world["approval_id"]
    admin2 = {"Authorization": "Bearer a2"}
    assert t2.get(f"/v1/approvals/{aid}").status_code == 404
    d = t2.post(f"/v1/approvals/{aid}/decide", json={"approve": True, "ttl_seconds": 60}, headers=admin2)
    assert d.status_code == 404
    assert t2.get("/v1/approvals").json()["approvals"] == []
    # t1's approval is still pending and nothing was granted
    v = world["t1"].get(f"/v1/approvals/{aid}").json()
    assert v["state"] == "pending"
    assert (
        world["t1"]
        .post("/v1/authorize", json=_auth("t1", world["chain1"][3]["context_id"]))
        .json()["decision"]
        == "HUMAN_REVIEW"
    )


def test_policy_reads_404_across_tenants(world):
    t2 = world["t2"]
    assert t2.get("/v1/policies/pol/versions/1").status_code == 404
    assert t2.get("/v1/policies").json()["policies"] == []
    assert t2.post("/v1/policies/pol/versions/1/activate").status_code == 404
    assert world["t1"].get("/v1/policies/pol/versions/1").status_code == 200  # t1 unaffected


def test_workload_grant_delegation_404_across_tenants(world):
    t1, t2 = world["t1"], world["t2"]
    assert t2.get("/v1/workloads").json()["workloads"] == []
    assert t2.get("/v1/grants").json()["grants"] == []
    assert t2.get("/v1/delegations").json()["delegations"] == []
    assert t2.patch("/v1/workloads/w-a", json={"status": "suspended"}).status_code == 404
    assert t2.post("/v1/workloads/w-a/grants", json={"principal_id": "mallory"}).status_code == 404
    assert t2.delete("/v1/workloads/w-a/grants/alice").status_code == 404
    assert t2.delete(f"/v1/delegations/{world['delegation_id']}").status_code == 404
    hand = t2.post("/v1/handoffs", json={"from_workload": "w-a", "to_workload": "w-b", "purpose": "rag"})
    assert hand.status_code == 200 and hand.json()["decision"] != "ALLOW"
    # t1 state intact
    assert [w["status"] for w in t1.get("/v1/workloads").json()["workloads"]] == ["active", "active"]
    assert [g["principal_id"] for g in t1.get("/v1/grants").json()["grants"]] == ["alice"]
    assert t1.get("/v1/delegations").json()["delegations"][0]["status"] == "active"


def test_metrics_are_tenant_scoped(world):
    t1, t2 = world["t1"], world["t2"]
    for _ in range(3):
        t1.post("/v1/authorize", json=_auth("t1", world["chain1"][0]["context_id"]))
    t2.post("/v1/authorize", json=_auth("t2", world["chain2"][0]["context_id"]))

    def decisions(tc) -> dict[str, int]:
        text = tc.get("/v1/metrics").text
        return {m[0]: int(m[1]) for m in re.findall(r'ales_authorize_total\{decision="(\w+)"\} (\d+)', text)}

    d1, d2 = decisions(t1), decisions(t2)
    assert sum(d1.values()) >= 3 and sum(d2.values()) == 1, (d1, d2)
    assert "t1" not in t2.get("/v1/metrics").text and "t2" not in t1.get("/v1/metrics").text


def test_audit_verify_and_head_are_tenant_scoped(world):
    t1, t2 = world["t1"], world["t2"]
    v1 = t1.get("/v1/audit/verify", headers=_h("a1-admin")).json()
    v2 = t2.get("/v1/audit/verify").json()
    assert v1["ok"] and v2["ok"]
    assert v1["records_checked"] > 0 and v2["records_checked"] > 0
    h1, h2 = t1.get("/v1/audit/head").json(), t2.get("/v1/audit/head").json()
    assert h1["tenant_id"] == "t1" and h2["tenant_id"] == "t2" and h1["head_hash"] != h2["head_hash"]
    # t2 doing more work moves only t2's chain
    for _ in range(2):
        t2.post("/v1/authorize", json=_auth("t2", world["chain2"][0]["context_id"]))
    now1 = t1.get("/v1/audit/head").json()
    assert (now1["seq"], now1["head_hash"]) == (h1["seq"], h1["head_hash"])
    assert t2.get("/v1/audit/head").json()["seq"] > h2["seq"]
    assert t2.get("/v1/audit/verify").json()["records_checked"] > v2["records_checked"]
    # a t2 credential cannot ask about t1's chain
    assert t2.get("/v1/audit/head", params={"tenant_id": "t1"}).status_code == 403


def test_snapshot_only_contains_own_tenant(world):
    snap = world["t2"].get("/v1/snapshot")
    assert snap.status_code == 200
    for env in world["chain1"]:
        assert env["context_id"] not in snap.text


# POSTs that are decisions (or session bookkeeping reported by SDKs), not tenant-state mutations
READ_OK_POSTS = {
    "/v1/authorize",
    "/v1/handoffs",
    "/v1/releases",
    "/v1/sessions/{session_id}/exposures",
    "/v1/sessions/{session_id}/reset",
}


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", lambda m: "1" if m.group(0) == "{version}" else "x", path)


def test_read_token_cannot_mutate_or_administer_any_route(world):
    """Walks the live OpenAPI table with a t1 *read-only* token. Only GETs and the two decision POSTs may
    get past authorization; every other route must answer 403 and leave state untouched."""
    app = world["app"]
    reader = TestClient(app, headers=_h("a1-read"))
    routes = sorted(
        (m.upper(), p) for p, ops in app.openapi()["paths"].items() if p.startswith("/v1") for m in ops
    )
    assert len(routes) >= 29
    admin_gets = {
        "/v1/admin/keys",
        "/v1/audit/verify",
        "/v1/policies",
        "/v1/policies/{policy_id}/versions/{version}",
        "/v1/approvals",
        "/v1/outbox/dead",
    }
    before = world["t1"].get("/v1/audit/head").json()
    seen_403 = 0
    for method, path in routes:
        if path in ("/v1/healthz", "/v1/readyz"):
            continue
        r = reader.request(method, _concrete(path), json={} if method in ("POST", "PATCH") else None)
        read_only = (method == "GET" and path not in admin_gets) or (
            method == "POST" and path in READ_OK_POSTS
        )
        if read_only:
            assert r.status_code not in (401, 403), (method, path, r.status_code)
        else:
            assert r.status_code == 403, (method, path, r.status_code, r.text[:120])
            assert "required" in r.json()["detail"]
            seen_403 += 1
    assert seen_403 >= 15
    # nothing mutated: no new tenant objects, still no revocation, governance state intact
    for env in world["chain1"]:
        out = world["t1"].post("/v1/authorize", json=_auth("t1", env["context_id"])).json()
        assert out["revocation_epoch"] == world["t1_epoch_baseline"]
    assert len(world["t1"].get("/v1/workloads").json()["workloads"]) == 2
    assert world["t1"].get("/v1/audit/head").json()["seq"] >= before["seq"]  # only decisions appended


def test_read_token_cannot_reach_other_tenant(world):
    reader = TestClient(world["app"], headers=_h("a1-read"))
    r = reader.post("/v1/authorize", json=_auth("t2", world["chain2"][0]["context_id"]))
    assert r.status_code == 403
    assert reader.get("/v1/audit/head", params={"tenant_id": "t2"}).status_code == 403
