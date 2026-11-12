import logging
import uuid

from ales_sdk import InvariantClient, new_derivative, new_source
from server_helpers import ALL, T2, TOKENS, P, TestClientTransport


def _chain(tenant="t1"):
    src = new_source(tenant, "doc", b"secret", "kb", classification="confidential")
    chunk = new_derivative("chunk", [src], tenant, "chunk", b"c")
    summ = new_derivative("summary", [chunk], tenant, "summary", b"s")
    return src, chunk, summ


def _register(client, src, chunk, summ):
    assert client.post("/v1/sources", json=src).status_code == 200
    assert client.post("/v1/derivations", json=chunk).status_code == 200
    r = client.post("/v1/derivations", json=summ)
    assert r.status_code == 200
    return r.json()


def _auth(client, cid, tenant="t1"):
    return client.post(
        "/v1/authorize",
        json={"tenant_id": tenant, "principal": P, "purpose": "rag", "objects": [{"context_id": cid}]},
    )


def test_healthz(client):
    assert client.get("/v1/healthz", headers={}).json() == {"status": "ok"}


def test_happy_path(client, caplog):
    src, chunk, summ = _chain()
    out = _register(client, src, chunk, summ)
    assert out["context_id"] == summ["context_id"] and out["object_version"] == "1"

    with caplog.at_level(logging.INFO, logger="ales.server"):
        r = _auth(client, summ["context_id"])
    body = r.json()
    assert r.status_code == 200 and body["decision"] == "ALLOW" and body["reason"] == ["OK"]
    epoch0 = body["revocation_epoch"]
    logged = " ".join(rec.getMessage() for rec in caplog.records)
    assert "alice" in logged and body["trace_id"] in logged and "secret" not in logged

    rev = client.post(
        "/v1/revocations", json={"tenant_id": "t1", "source_id": src["context_id"], "reason": "acl_changed"}
    )
    assert rev.status_code == 200
    assert rev.json()["revocation_epoch"] == epoch0 + 1 and rev.json()["event_id"]

    body = _auth(client, summ["context_id"]).json()
    assert body["decision"] == "DENY"
    assert "ANCESTOR_ACL_REVOKED" in body["reason"]
    assert body["revocation_epoch"] == epoch0 + 1


def test_verify(client):
    r = client.post("/v1/verify", json={"tenant_id": "t1", "adapter": "langgraph", "mode": "strict"})
    body = r.json()
    assert r.status_code == 200 and body["passed"] is True
    assert body["adapter"] == "langgraph" and body["mode"] == "strict"
    assert len(body["checks"]) >= 4 and all(c["passed"] for c in body["checks"])
    assert client.post("/v1/verify", json={"tenant_id": "t1", "adapter": "x", "mode": "strict"}).json()["passed"]


def test_missing_parent_422(client):
    _src, chunk, _ = _chain()
    r = client.post("/v1/derivations", json=chunk)  # source never registered
    assert r.status_code == 422


def test_duplicate_digest_409(client):
    src = new_source("t1", "doc", b"a", "kb")
    assert client.post("/v1/sources", json=src).status_code == 200
    assert client.post("/v1/sources", json=src).status_code == 200  # idempotent
    other = dict(src, content_digest=new_source("t1", "doc", b"b", "kb")["content_digest"])
    assert client.post("/v1/sources", json=other).status_code == 409


def test_authority_widening_409(client):
    src = new_source("t1", "doc", b"a", "kb", classification="confidential")
    client.post("/v1/sources", json=src)
    chunk = new_derivative("chunk", [src], "t1", "c", b"c", classification="public")
    assert client.post("/v1/derivations", json=chunk).status_code == 409


def test_invalid_envelope_422(client):
    src = new_source("t1", "doc", b"a", "kb")
    src["content_digest"] = "nope"
    assert client.post("/v1/sources", json=src).status_code == 422


def test_lineage_shape(client):
    src, chunk, summ = _chain()
    _register(client, src, chunk, summ)
    r = client.get(f"/v1/lineage/{chunk['context_id']}", params={"tenant_id": "t1"})
    body = r.json()
    assert r.status_code == 200 and body["context_id"] == chunk["context_id"]
    assert body["ancestors"] == [
        {"context_id": src["context_id"], "object_version": "1", "kind": "source", "tombstoned": False}
    ]
    assert body["descendants"] == [
        {"context_id": summ["context_id"], "object_version": "1", "kind": "summary", "tombstoned": False}
    ]
    client.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"},
                headers={"X-Tenant-Id": "t1"})
    body = client.get(f"/v1/lineage/{chunk['context_id']}", params={"tenant_id": "t1"}).json()
    assert body["ancestors"][0]["tombstoned"] is True and body["descendants"][0]["tombstoned"] is True
    assert client.get(f"/v1/lineage/{chunk['context_id']}", params={"tenant_id": "t2"}, headers=T2).status_code == 404
    # asking for another tenant's lineage with t1's credential is a spoof, not a 404
    assert client.get(f"/v1/lineage/{chunk['context_id']}", params={"tenant_id": "t2"}).status_code == 403


def test_tenant_header_mismatch_403(client):
    src = new_source("t1", "doc", b"a", "kb")
    h = {**client.headers, "X-Tenant-Id": "t2"}
    expect = {"detail": "tenant mismatch with credential"}
    r = client.post("/v1/sources", json=src, headers=h)
    assert r.status_code == 403 and r.json() == expect
    body = {"tenant_id": "t1", "principal": P, "purpose": "rag", "objects": [{"context_id": "x"}]}
    assert client.post("/v1/authorize", json=body, headers=h).status_code == 403
    rev = {"tenant_id": "t1", "source_id": "s", "reason": "deleted"}
    assert client.post("/v1/revocations", json=rev, headers=h).status_code == 403
    assert client.get("/v1/lineage/x", params={"tenant_id": "t1"}, headers=h).status_code == 403
    assert client.post("/v1/verify", json={"tenant_id": "t1"}, headers=h).status_code == 403


def test_cross_tenant_denied(client):
    src, chunk, summ = _chain("t1")
    _register(client, src, chunk, summ)
    # tenant t2's own credential asking about t1's object: denied, not leaked
    r = client.post("/v1/authorize", json=_auth_body(summ["context_id"], "t2"), headers=T2)
    body = r.json()
    assert r.status_code == 200 and body["decision"] == "DENY" and body["reason"] == ["TENANT_MISMATCH"]


def _auth_body(cid, tenant):
    return {"tenant_id": tenant, "principal": P, "purpose": "rag", "objects": [{"context_id": cid}]}


def test_sdk_end_to_end(make_client):
    tokens = {**TOKENS, "tok-sdk": {"tenant_id": "sdk-t", "roles": ALL, "subject": "sdk-service"}}
    client = make_client(tokens=tokens)
    with InvariantClient(
        "http://testserver", "sdk-t", "tok-sdk", transport=TestClientTransport(client)
    ) as sdk:
        assert sdk.healthz() == {"status": "ok"}
        src = new_source("sdk-t", "kb/handbook.md", "Confidential handbook", "demo-kb", classification="confidential")
        assert sdk.register_source(src)["context_id"] == src["context_id"]
        chunk = new_derivative("chunk", [src], "sdk-t", "chunk", b"c")
        assert sdk.register_derivation(chunk)["context_id"] == chunk["context_id"]

        r = sdk.authorize(P, "rag", [chunk["context_id"]], agent_id="ag", session_id="s1")
        assert r.decision == "ALLOW" and r.allowed and r.revocation_epoch == 0
        assert r.objects[0].context_id == chunk["context_id"]

        lin = sdk.lineage(chunk["context_id"])
        assert [a["context_id"] for a in lin["ancestors"]] == [src["context_id"]]

        out = sdk.submit_revocation({"source_id": src["context_id"], "reason": "deleted", "actor": "demo"})
        assert out["revocation_epoch"] == 1 and uuid.UUID(out["event_id"])

        r2 = sdk.authorize(P, "rag", [chunk["context_id"]])
        assert r2.decision == "DENY" and not r2.from_cache
        assert r2.reason == ["ANCESTOR_DELETED"]
        assert sdk.verify("langgraph", "strict")["passed"] is True
