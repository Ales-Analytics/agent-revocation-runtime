"""Lifecycle value layer over HTTP: impact preview, decision explanation, transformation registry + rebuilds,
durable sessions, release-gate entitlements, tenant isolation."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import timedelta

import pytest
from ales_core import AuditLog, RebuildInput, RebuildOutput
from ales_sdk import new_derivative, new_source
from ales_server import create_app
from ales_server.config import ConfigError
from ales_server.lifecycle import UNINSTRUMENTED_NOTE, parse_duration
from fastapi.testclient import TestClient
from server_helpers import T1, T2, TOKENS, P, authorize_body, bearer, chain
from sqlalchemy import select

ADMIN = bearer("tok-t1-admin")
READER = bearer("tok-t1-read")
INGEST = bearer("tok-t1-ingest")


def _register_chain(c, headers=None, tenant="t1"):
    src, chunk, summ = chain(tenant)
    assert c.post("/v1/sources", json=src, headers=headers).status_code == 200
    for env in (chunk, summ):
        assert c.post("/v1/derivations", json=env, headers=headers).status_code == 200
    return src, chunk, summ


def _revoke(c, source_id, reason="acl_changed", version=None, headers=None):
    body = {"source_id": source_id, "reason": reason}
    if version:
        body["source_version"] = version
    r = c.post("/v1/revocations", json=body, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def _report(c, sid, cids, headers=None, principal=P, workload=None):
    body = {"principal": principal, "exposures": [{"context_id": x, "version": v} for x, v in cids]}
    if workload:
        body["workload"] = workload
    return c.post(f"/v1/sessions/{sid}/exposures", json=body, headers=headers)


# ============================================================================================== impact
def test_impact_preview_lists_blast_radius_before_revocation(client):
    src, chunk, summ = _register_chain(client)
    # nothing reported yet: honest "unknown", never a claimed zero
    r = client.get(f"/v1/impact/{src['context_id']}")
    assert r.status_code == 200
    body = r.json()
    assert body["exposed_sessions"] == {"status": "unknown", "count": None, "ids": [], "truncated": False}
    assert body["uninstrumented_note"] == UNINSTRUMENTED_NOTE
    assert [(d["context_id"], d["kind"]) for d in body["descendants"]] == sorted(
        [(chunk["context_id"], "chunk"), (summ["context_id"], "summary")]
    )
    assert body["stores"] == ["chunk", "source", "summary"]
    assert body["pending_cleanup"] == {"count": 0, "by_state": {}, "by_store_kind": {}}
    assert body["source"]["versions"][0]["kind"] == "source" and body["rebuildable"] == []

    assert _report(client, "sess-1", [(summ["context_id"], summ["object_version"])]).status_code == 200
    assert _report(client, "sess-2", [("not-related", "1")]).status_code == 200
    body = client.get(f"/v1/impact/{src['context_id']}", params={"version": src["object_version"]}).json()
    assert body["exposed_sessions"]["status"] == "recorded"
    assert (body["exposed_sessions"]["count"], body["exposed_sessions"]["ids"]) == (1, ["sess-1"])
    # a tenant that reports sessions but none touch this lineage: "none", not "unknown"
    other = _register_chain(client)[0]
    assert client.get(f"/v1/impact/{other['context_id']}").json()["exposed_sessions"]["status"] == "none"

    _revoke(client, src["context_id"])
    after = client.get(f"/v1/impact/{src['context_id']}").json()
    assert after["pending_cleanup"]["count"] == 3  # revocation queued purge rows (log-only worker disabled)
    assert after["pending_cleanup"]["by_state"] == {"pending": 3}
    with client.app.state.session_factory() as s:
        recs = list(s.scalars(select(AuditLog).where(AuditLog.action == "impact.preview")))
    assert len(recs) == 4 and recs[0].actor == "svc-t1" and recs[0].detail["descendants"] == 2


def test_impact_is_tenant_scoped_and_404s(client):
    src, _, _ = _register_chain(client)
    assert client.get(f"/v1/impact/{src['context_id']}", headers=T2).status_code == 404  # foreign == unknown
    assert client.get("/v1/impact/00000000-0000-0000-0000-000000000000").status_code == 404
    assert client.get(f"/v1/impact/{src['context_id']}", params={"version": "nope"}).status_code == 404
    assert client.get(f"/v1/impact/{src['context_id']}", headers=READER).status_code == 200  # read role suffices
    t2_src = _register_chain(client, headers=T2, tenant="t2")[0]
    assert client.get(f"/v1/impact/{t2_src['context_id']}").status_code == 404
    # t2's session reports never leak into t1's preview
    assert _report(client, "s", [(src["context_id"], None)], headers=T2).status_code == 200
    assert client.get(f"/v1/impact/{src['context_id']}").json()["exposed_sessions"]["status"] == "unknown"


# ============================================================================================ explanation
def test_decision_explanation_after_revocation(client):
    src, chunk, summ = _register_chain(client)
    _revoke(client, src["context_id"], "deleted")
    resp = client.post("/v1/authorize", json=authorize_body("t1", summ["context_id"])).json()
    assert resp["decision"] == "DENY"
    r = client.get(f"/v1/decisions/{resp['trace_id']}")
    assert r.status_code == 200
    e = r.json()
    assert e["decision"] == "DENY" and e["reasons"] == ["ANCESTOR_DELETED"] and e["kind"] == "authorize"
    ids = [[n["context_id"] for n in p] for p in e["dependency_paths"]]
    assert ids == [[src["context_id"], chunk["context_id"], summ["context_id"]]]
    assert [n["kind"] for n in e["dependency_paths"][0]] == ["source", "chunk", "summary"]
    assert [(c["context_id"], c["reason"]) for c in e["causes"]] == [(src["context_id"], "deleted")]
    assert e["objects"][0]["causes"][0]["context_id"] == src["context_id"]
    assert e["objects"][0]["causes"][0]["reason"] == "deleted"
    assert e["authority"]["revocation_epoch"] == resp["revocation_epoch"] == 1
    assert e["authority"]["policy_version"] == resp["policy_version"]
    assert {c["context_id"] for c in e["cleanup"]} == {src["context_id"], chunk["context_id"], summ["context_id"]}
    assert all(c["state"] == "pending" for c in e["cleanup"])
    text = client.get(f"/v1/decisions/{resp['trace_id']}", params={"format": "text"})
    assert text.headers["content-type"].startswith("text/plain")
    for needle in ("Decision: DENY", "Dependent source:", "Reason: ANCESTOR_DELETED", "Dependency path:",
                   "Authority observed:", "Cleanup:", src["context_id"]):
        assert needle in text.text


def test_allow_and_release_decisions_are_explainable_and_isolated(client):
    _, _, summ = _register_chain(client)
    ok = client.post("/v1/authorize", json=authorize_body("t1", summ["context_id"])).json()
    e = client.get(f"/v1/decisions/{ok['trace_id']}").json()
    assert e["decision"] == "ALLOW" and e["dependency_paths"] == [] and e["reasons"] == ["OK"]
    rel = client.post(
        "/v1/releases",
        json={"principal": P, "action": "send", "destination": "mail", "purpose": "rag",
              "objects": [{"context_id": summ["context_id"]}]},
    )
    assert rel.status_code == 200
    with client.app.state.session_factory() as s:
        trace = s.scalars(select(AuditLog).where(AuditLog.action == "release.authorize")).one().detail["trace_id"]
    assert client.get(f"/v1/decisions/{trace}").json()["kind"] == "release"
    # another tenant (even with every role) and unknown traces are indistinguishable 404s
    assert client.get(f"/v1/decisions/{ok['trace_id']}", headers=T2).status_code == 404
    assert client.get("/v1/decisions/not-a-trace").status_code == 404
    assert client.get(f"/v1/decisions/{'x' * 300}").status_code == 422  # over-long trace id


def test_explanation_for_scope_denial_walks_to_lineage_roots(client):
    src = new_source("t1", "d", b"x", "kb", principal_scope=["bob"])
    assert client.post("/v1/sources", json=src).status_code == 200
    chunk = new_derivative("chunk", [src], "t1", "c", b"c")
    assert client.post("/v1/derivations", json=chunk).status_code == 200
    resp = client.post("/v1/authorize", json=authorize_body("t1", chunk["context_id"])).json()
    assert resp["decision"] == "DENY" and resp["reason"] == ["PRINCIPAL_NOT_IN_SCOPE"]
    e = client.get(f"/v1/decisions/{resp['trace_id']}").json()
    assert e["objects"][0]["causes"] == []  # no revocation: the lineage roots are shown instead
    assert [n["context_id"] for n in e["dependency_paths"][0]] == [src["context_id"], chunk["context_id"]]


# ============================================================================ transformations + rebuilds
def _upper(inputs: list[RebuildInput]) -> RebuildOutput:
    blob = "|".join(i.content_digest for i in inputs).upper()
    return RebuildOutput("sha256:" + hashlib.sha256(blob.encode()).hexdigest())


def _tr(c, tid="upper", headers=ADMIN, **over):
    body = {"transformation_id": tid, "version": "1", "input_kinds": ["source"], "output_kind": "chunk",
            "implementation_ref": "impl://upper", "idempotent": True, **over}
    return c.post("/v1/transformations", json=body, headers=headers)


def _rebuild_world(c):
    src = new_source("t1", "doc", b"v1", "kb")
    assert c.post("/v1/sources", json=src).status_code == 200
    assert _tr(c).status_code == 201
    chunk = new_derivative("chunk", [src], "t1", "chunk", b"c")
    assert c.post("/v1/derivations", json=chunk).status_code == 200
    r = c.post(
        f"/v1/derivations/{chunk['context_id']}/{chunk['object_version']}/transformation",
        json={"transformation_id": "upper", "version": "1"},
    )
    assert r.status_code == 200, r.text
    time.sleep(0.01)
    v2 = new_source("t1", "doc", b"v2", "kb", object_version="2", context_id=src["context_id"])
    assert c.post("/v1/sources", json=v2).status_code == 200
    _revoke(c, src["context_id"], "version_superseded", version=src["object_version"])
    return src, chunk, v2


def test_transformation_registry_roles_and_conflicts(client):
    assert _tr(client).status_code == 201
    assert _tr(client).status_code == 201  # identical re-registration is idempotent
    assert _tr(client, implementation_ref="impl://other").status_code == 409
    assert _tr(client, tid="bad", output_kind="source").status_code == 422
    assert _tr(client, headers=READER).status_code == 403
    assert _tr(client, tid="other-tenant", headers=T2).status_code == 201
    listed = client.get("/v1/transformations", headers=READER).json()["transformations"]
    assert [t["transformation_id"] for t in listed] == ["upper"]  # per tenant
    r = client.post(f"/v1/derivations/{'0' * 8}-0000-0000-0000-{'0' * 12}/1/transformation",
                    json={"transformation_id": "upper", "version": "1"})
    assert r.status_code == 404


def test_rebuild_end_to_end_creates_new_derivation_only():
    app = create_app(
        "sqlite://", tokens=TOKENS, outbox_interval=0, rebuild_handlers={"upper": _upper}, env={}
    )
    with TestClient(app, headers=T1) as c:
        src, chunk, _ = _rebuild_world(c)
        old = c.post("/v1/authorize", json=authorize_body("t1", chunk["context_id"])).json()
        assert old["decision"] == "REFRESH"
        assert c.post(f"/v1/rebuilds/{src['context_id']}/{src['object_version']}", headers=READER).status_code == 403
        r = c.post(f"/v1/rebuilds/{src['context_id']}/{src['object_version']}", headers=ADMIN)
        assert r.status_code == 200 and r.json()["planned"] == 1
        job = r.json()["jobs"][0]
        assert job["state"] == "pending" and job["inputs"] == [
            {"context_id": src["context_id"], "object_version": "2"}
        ]
        # impact preview now names the rebuildable derivative
        imp = c.get(f"/v1/impact/{src['context_id']}", params={"version": "1"}).json()
        assert [x["transformation_id"] for x in imp["rebuildable"]] == ["upper"]
        # tenant 2 cannot run, list or enqueue t1's rebuilds
        assert c.post(f"/v1/rebuilds/{src['context_id']}/1", headers=T2).status_code == 404
        assert c.get("/v1/rebuilds", headers=T2).json()["jobs"] == []
        assert c.post("/v1/rebuilds/run", headers=T2).json()["leased"] == 0

        run = c.post("/v1/rebuilds/run", headers=ADMIN).json()
        assert (run["leased"], run["done"], run["failed"]) == (1, 1, 0)
        done = c.get("/v1/rebuilds", params={"state": "done"}).json()["jobs"]
        assert len(done) == 1 and done[0]["result"] is not None
        new = done[0]["result"]
        body = authorize_body("t1", new["context_id"])
        body["objects"][0]["version"] = new["object_version"]
        assert c.post("/v1/authorize", json=body).json()["decision"] == "ALLOW"
        again = c.post("/v1/authorize", json=authorize_body("t1", chunk["context_id"])).json()
        assert again["decision"] == "REFRESH"  # the old derivative is untouched
        lin = c.get(f"/v1/lineage/{new['context_id']}").json()
        assert [a["context_id"] for a in lin["ancestors"]] == [src["context_id"]]
        assert c.post(f"/v1/rebuilds/{src['context_id']}/1", headers=ADMIN).json()["planned"] == 0  # already rebuilt
        with app.state.session_factory() as s:
            actions = {a.action for a in s.scalars(select(AuditLog).where(AuditLog.tenant_id == "t1"))}
        assert {"transformation.register", "derivation.tag_transformation", "rebuild.enqueue",
                "rebuild.complete"} <= actions


def test_rebuild_without_handler_fails_with_clear_error(client):
    src, chunk, _ = _rebuild_world(client)
    r = client.post(f"/v1/rebuilds/{src['context_id']}/{src['object_version']}", headers=ADMIN)
    assert r.json()["planned"] == 1
    run = client.post("/v1/rebuilds/run", headers=ADMIN).json()
    assert (run["leased"], run["failed"], run["done"]) == (1, 1, 0)
    failed = client.get("/v1/rebuilds", params={"state": "failed"}).json()["jobs"]
    assert "no rebuild handler registered for transformation 'upper'" in failed[0]["last_error"]
    assert failed[0]["result"] is None
    # nothing was registered in place of the stale derivative
    assert client.post("/v1/authorize", json=authorize_body("t1", chunk["context_id"])).json()["decision"] == "REFRESH"


# ================================================================================================ sessions
def test_session_exposure_flag_and_reset_flow(client):
    src, chunk, summ = _register_chain(client)
    r = _report(client, "s1", [(summ["context_id"], summ["object_version"])], workload="agent-1")
    assert r.status_code == 200
    assert (r.json()["recorded"], r.json()["generation"], r.json()["needs_reset"]) == (1, 0, False)
    _report(client, "s2", [(chunk["context_id"], None)])
    _report(client, "innocent", [("elsewhere", "1")])
    _revoke(client, src["context_id"])
    s1 = client.get("/v1/sessions/s1").json()
    assert s1["needs_reset"] is True and s1["flag_reason"].startswith("revocation:") and s1["exposure_count"] == 1
    assert client.get("/v1/sessions/s2").json()["needs_reset"] is True  # unversioned exposure matches any version
    assert client.get("/v1/sessions/innocent").json()["needs_reset"] is False
    # a reset (by a read-role SDK) bumps the generation and clears the flag
    rr = client.post("/v1/sessions/s1/reset", headers=READER)
    assert rr.status_code == 200
    assert (rr.json()["generation"], rr.json()["needs_reset"], rr.json()["exposure_count"]) == (1, False, 0)
    with client.app.state.session_factory() as s:
        acts = [a.action for a in s.scalars(select(AuditLog).where(AuditLog.tenant_id == "t1"))]
    assert "session.flag" in acts and "session.reset" in acts


def test_sessions_are_tenant_scoped_and_validated(client):
    src, _, _ = _register_chain(client)
    assert _report(client, "shared-name", [(src["context_id"], None)]).status_code == 200
    assert client.get("/v1/sessions/shared-name", headers=T2).status_code == 404
    assert client.post("/v1/sessions/shared-name/reset", headers=T2).status_code == 404
    assert _report(client, "shared-name", [(src["context_id"], None)], headers=T2).status_code == 200
    assert client.post("/v1/sessions/shared-name/reset", headers=T2).json()["generation"] == 1
    assert client.get("/v1/sessions/shared-name").json()["generation"] == 0  # t1's session untouched
    assert client.post("/v1/sessions/nope/reset").status_code == 404
    assert client.get("/v1/sessions/nope").status_code == 404
    bad = client.post("/v1/sessions/x/exposures", json={"principal": P, "exposures": []})
    assert bad.status_code == 422
    too_many = {"principal": P, "exposures": [{"context_id": f"c{i}"} for i in range(1001)]}
    assert client.post("/v1/sessions/x/exposures", json=too_many).status_code == 422
    assert client.post("/v1/sessions/x/exposures", json={"principal": P, "tenant_id": "t2",
                       "exposures": [{"context_id": "c"}]}).status_code == 403


def test_exposures_survive_restart_and_expire(tmp_path):
    url = f"sqlite:///{tmp_path / 'ales.db'}"
    kw = {"tokens": TOKENS, "outbox_interval": 0, "env": {"ALES_SESSION_RETENTION": "1h"}}
    with TestClient(create_app(url, **kw), headers=T1) as c1:
        src, _, summ = _register_chain(c1)
        assert _report(c1, "durable", [(summ["context_id"], summ["object_version"])]).status_code == 200
    # a brand new app + process-equivalent: the server still remembers, and a revocation still flags
    with TestClient(create_app(url, **kw), headers=T1) as c2:
        assert c2.get("/v1/sessions/durable").json()["exposure_count"] == 1
        _revoke(c2, src["context_id"])
        assert c2.get("/v1/sessions/durable").json()["needs_reset"] is True
        later = c2.app.state.clock() + timedelta(hours=2)
        c2.app.state.clock = lambda: later
        assert c2.get("/v1/sessions/durable").status_code == 404  # bounded retention: forgotten once lapsed


def test_session_retention_config():
    assert parse_duration(None) == timedelta(days=7)
    assert parse_duration("12h") == timedelta(hours=12) and parse_duration("90") == timedelta(seconds=90)
    for bad in ("0", "abc", "999d", "-1d", "1w"):
        with pytest.raises(ConfigError):
            parse_duration(bad)
    with pytest.raises(ConfigError):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_SESSION_RETENTION": "soon"})


# ==================================================================== release gate resolves entitlements
def _ent_app(doc):
    return create_app(
        "sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_ENTITLEMENTS": json.dumps(doc)}
    )


def _release(c, cid, principal=P):
    return c.post(
        "/v1/releases",
        json={"principal": principal, "action": "send", "destination": "mail", "purpose": "rag",
              "objects": [{"context_id": cid}]},
    )


def test_release_resolves_group_entitlements_like_authorize():
    app = _ent_app({"t1": {"alice": ["eng"], "carol": []}})
    with TestClient(app, headers=T1) as c:
        src = new_source("t1", "d", b"x", "kb", principal_scope=["group:eng"])
        assert c.post("/v1/sources", json=src).status_code == 200
        auth = c.post("/v1/authorize", json=authorize_body("t1", src["context_id"])).json()
        assert auth["decision"] == "ALLOW"
        member = _release(c, src["context_id"]).json()
        assert member["decision"] == "ALLOW"  # was DENY before R46 was closed
        outsider = _release(c, src["context_id"], principal={"type": "user", "id": "carol"}).json()
        assert outsider["decision"] == "DENY"
        with app.state.session_factory() as s:
            rec = next(a.detail for a in s.scalars(select(AuditLog).where(AuditLog.action == "release.authorize")))
        assert rec["policy"]["entitlement_status"] == "resolved" and rec["policy"]["groups"] == ["eng"]
        # caller-asserted groups are not part of the release body at all
        bad = c.post("/v1/releases", json={"principal": P, "action": "a", "destination": "d", "purpose": "p",
                                           "groups": ["eng"], "objects": [{"context_id": src["context_id"]}]})
        assert bad.status_code == 422


def test_release_with_unavailable_required_entitlements_is_not_allowed():
    app = _ent_app({"t1": {"alice": ["eng"]}})
    with TestClient(app, headers=T1) as c:
        src = new_source("t1", "d", b"x", "kb", principal_scope=["group:eng"])
        assert c.post("/v1/sources", json=src).status_code == 200
        # no entitlement entry for this principal and a group-only scope: fail closed
        r = _release(c, src["context_id"], principal={"type": "user", "id": "nobody"}).json()
        assert r["decision"] != "ALLOW"


def test_approval_issuer_binding_end_to_end():
    """An approval granted to alice@A does not cover alice@B (fingerprints are issuer-aware)."""
    app = create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={})
    with TestClient(app, headers=T1) as c:
        _, _, summ = _register_chain(c)
        pol = {
            "policy_id": "p", "version": 1, "default_action": "allow",
            "rules": [{"rule_id": "hr", "effect": "human_review", "subjects": {"principals": ["alice"]}}],
        }
        assert c.post("/v1/policies", json=pol, headers=ADMIN).status_code == 201
        assert c.post("/v1/policies/p/versions/1/activate", headers=ADMIN).status_code == 200
        a = {"type": "user", "id": "alice", "issuer": "https://idp-a"}
        b = {"type": "user", "id": "alice", "issuer": "https://idp-b"}

        def ask(principal):
            body = authorize_body("t1", summ["context_id"])
            body["principal"] = principal
            return c.post("/v1/authorize", json=body).json()

        assert ask(a)["decision"] == "HUMAN_REVIEW"
        pend = c.get("/v1/approvals", headers=ADMIN).json()
        items = pend.get("approvals", pend) if isinstance(pend, dict) else pend
        assert items and items[0]["requested_by_issuer"] == "https://idp-a"
        aid = items[0]["approval_id"]
        d = c.post(f"/v1/approvals/{aid}/decide", json={"approve": True, "ttl_seconds": 600}, headers=ADMIN)
        assert d.status_code == 200, d.text
        assert ask(a)["decision"] == "ALLOW"
        assert ask(b)["decision"] == "HUMAN_REVIEW"  # other issuer: a fresh, separate approval


def test_audit_chain_intact_after_lifecycle_writes(client):
    src, _, summ = _register_chain(client)
    _report(client, "s", [(summ["context_id"], None)])
    client.get(f"/v1/impact/{src['context_id']}")
    _revoke(client, src["context_id"])
    client.post("/v1/sessions/s/reset")
    assert client.get("/v1/audit/verify", headers=ADMIN).json()["ok"] is True
    assert json.dumps(client.get("/v1/sessions/s").json())
