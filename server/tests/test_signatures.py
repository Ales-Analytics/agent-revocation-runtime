"""Signature ingress (require_signatures) and issuer-key administration."""

from __future__ import annotations

import uuid

import pytest
from ales_core import AuditLog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from server_helpers import T1, T2, TOKENS, bearer, chain, pub_b64, sign_env, sign_event
from sqlalchemy import select


@pytest.fixture
def sclient(make_client):
    return make_client(require_signatures=True)


def _register_key(c, key, key_id="k1", headers=None):
    r = c.post("/v1/admin/keys", json={"key_id": key_id, "public_key_b64": pub_b64(key)}, headers=headers or {})
    assert r.status_code == 201, r.text
    return r.json()


def _signed_chain(key, key_id="k1", tenant="t1"):
    src, chunk, summ = chain(tenant)
    return [sign_env(e, key, key_id) for e in (src, chunk, summ)]


def _audit_actions(c, tenant="t1"):
    with c.app.state.session_factory() as s:
        return [(r.action, r.actor, r.detail) for r in s.scalars(select(AuditLog).where(AuditLog.tenant_id == tenant))]


# ------------------------------------------------------------------------------------ rejections
def test_unsigned_envelopes_and_events_rejected_missing_signature(sclient):
    src, chunk, _ = chain()
    for path, body in (("/v1/sources", src), ("/v1/derivations", chunk)):
        r = sclient.post(path, json=body)
        assert r.status_code == 403 and r.json() == {"detail": "missing_signature"}
    ev = {"event_id": str(uuid.uuid4()), "tenant_id": "t1", "source_id": src["context_id"], "reason": "deleted",
          "effective_at": "2026-01-01T00:00:00Z"}
    r = sclient.post("/v1/revocations", json=ev)
    assert r.status_code == 403 and r.json() == {"detail": "missing_signature"}
    # a rejected revocation must not advance the epoch
    assert sclient.get("/v1/snapshot").json()["revocation_epoch"] == 0
    # and a rejected source is not registered
    assert sclient.get(f"/v1/lineage/{src['context_id']}").status_code == 404


def test_empty_and_non_string_signature_rejected(sclient):
    src = chain()[0]
    for sig in ("", None):
        r = sclient.post("/v1/sources", json={**src, "signature": sig, "issuer_key_id": "k1"})
        assert r.status_code == 403 and r.json()["detail"] == "missing_signature"


def test_signed_with_unknown_key_rejected(sclient):
    key = Ed25519PrivateKey.generate()
    src, *_ = _signed_chain(key, "never-registered")
    r = sclient.post("/v1/sources", json=src)
    assert r.status_code == 403 and r.json() == {"detail": "unknown_key"}


def test_signature_without_key_id_rejected(sclient):
    key = Ed25519PrivateKey.generate()
    _register_key(sclient, key)
    src = sign_env(chain()[0], key, "k1")
    src["issuer_key_id"] = None
    assert sclient.post("/v1/sources", json=src).json() == {"detail": "unknown_key"}


@pytest.mark.parametrize("new_status", ["retired", "revoked"])
def test_signed_with_inactive_key_rejected(sclient, new_status):
    key = Ed25519PrivateKey.generate()
    _register_key(sclient, key)
    src, chunk, _ = _signed_chain(key)
    assert sclient.post("/v1/sources", json=src).status_code == 200  # fine while active
    r = sclient.patch("/v1/admin/keys/k1", json={"status": new_status})
    assert r.status_code == 200 and r.json()["status"] == new_status
    r = sclient.post("/v1/derivations", json=chunk)
    assert r.status_code == 403 and r.json() == {"detail": "key_not_active"}
    ev = sign_event(
        {"event_id": str(uuid.uuid4()), "tenant_id": "t1", "source_id": src["context_id"], "reason": "deleted",
         "effective_at": "2026-01-01T00:00:00Z"}, key, "k1")
    r = sclient.post("/v1/revocations", json=ev)
    assert r.status_code == 403 and r.json() == {"detail": "key_not_active"}


def test_tampered_after_signing_rejected(sclient):
    key = Ed25519PrivateKey.generate()
    _register_key(sclient, key)
    src = _signed_chain(key)[0]
    for field, value in (("classification", "public"), ("object_id", "other"), ("policy_version", "p9"),
                         ("principal_scope", ["mallory"])):
        r = sclient.post("/v1/sources", json={**src, field: value})
        assert r.status_code == 403 and r.json() == {"detail": "bad_signature"}, field
    assert sclient.post("/v1/sources", json=src).status_code == 200


def test_garbage_signature_rejected(sclient):
    key = Ed25519PrivateKey.generate()
    _register_key(sclient, key)
    src = _signed_chain(key)[0]
    for sig in ("not base64 !!", "AAAA", "A" * 86 + "=="):
        r = sclient.post("/v1/sources", json={**src, "signature": sig})
        assert r.status_code == 403 and r.json() == {"detail": "bad_signature"}, sig


def test_signed_by_a_different_key_rejected(sclient):
    registered, attacker = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    _register_key(sclient, registered)
    src = _signed_chain(attacker)[0]  # claims issuer k1 but signed by the attacker's key
    r = sclient.post("/v1/sources", json=src)
    assert r.status_code == 403 and r.json() == {"detail": "bad_signature"}


def test_another_tenants_key_cannot_vouch(sclient):
    key = Ed25519PrivateKey.generate()
    _register_key(sclient, key, "t2-key", headers=T2)  # registered by tenant t2's admin
    src = sign_env(chain("t1")[0], key, "t2-key")
    r = sclient.post("/v1/sources", json=src)  # tenant t1 ingress
    assert r.status_code == 403 and r.json() == {"detail": "unknown_key"}  # true reason audited, not leaked


def test_events_signed_but_wrong_tenant_body_is_a_tenant_spoof_first(sclient):
    key = Ed25519PrivateKey.generate()
    _register_key(sclient, key, "k2", headers=T2)
    src2 = sign_env(chain("t2")[0], key, "k2")
    assert sclient.post("/v1/sources", json=src2).status_code == 403  # t1 token, t2 body


def test_revocation_defaults_cannot_be_signed_around(sclient):
    """A signed event that leaves event_id/effective_at to the server fails: the server-filled values
    were not covered by the signature."""
    key = Ed25519PrivateKey.generate()
    _register_key(sclient, key)
    src = _signed_chain(key)[0]
    assert sclient.post("/v1/sources", json=src).status_code == 200
    ev = sign_event({"event_id": str(uuid.uuid4()), "tenant_id": "t1", "source_id": src["context_id"],
                     "reason": "deleted", "effective_at": "2026-01-01T00:00:00Z"}, key, "k1")
    stripped = {k: v for k, v in ev.items() if k != "event_id"}
    r = sclient.post("/v1/revocations", json=stripped)
    assert r.status_code == 403 and r.json() == {"detail": "bad_signature"}


def test_rejections_are_audited_without_registering(sclient):
    src = chain()[0]
    sclient.post("/v1/sources", json=src)
    rows = [r for r in _audit_actions(sclient) if r[0] == "ingress.rejected"]
    assert len(rows) == 1
    _, actor, detail = rows[0]
    assert actor == "svc-t1" and detail["reason"] == "missing_signature" and detail["what"] == "source"
    assert detail["ref"] == src["context_id"]
    assert not any(a == "source.register" for a, *_ in _audit_actions(sclient))


def test_huge_attacker_controlled_key_id_does_not_break_ingress(sclient):
    src = {**chain()[0], "issuer_key_id": "k" * 5000, "signature": "AAAA"}
    r = sclient.post("/v1/sources", json=src)
    assert r.status_code == 403 and r.json() == {"detail": "unknown_key"}


# ---------------------------------------------------------------------------------------- accepts
def test_valid_signed_flow_accepted(sclient):
    key = Ed25519PrivateKey.generate()
    _register_key(sclient, key)
    src, chunk, summ = _signed_chain(key)
    assert sclient.post("/v1/sources", json=src).status_code == 200
    assert sclient.post("/v1/derivations", json=chunk).status_code == 200
    assert sclient.post("/v1/derivations", json=summ).status_code == 200
    ev = sign_event({"event_id": str(uuid.uuid4()), "tenant_id": "t1", "source_id": src["context_id"],
                     "reason": "acl_changed", "effective_at": "2026-01-01T00:00:00Z", "actor": "alice"}, key, "k1")
    r = sclient.post("/v1/revocations", json=ev)
    assert r.status_code == 200 and r.json()["revocation_epoch"] == 1
    actions = [a for a, *_ in _audit_actions(sclient)]
    assert actions.count("source.register") == 1 and actions.count("derivation.register") == 2
    assert "revocation.accept" in actions


def test_unsigned_accepted_when_signature_mode_off(client):
    src, chunk, _ = chain()
    assert client.post("/v1/sources", json=src).status_code == 200
    assert client.post("/v1/derivations", json=chunk).status_code == 200


def test_signature_mode_from_env():
    from ales_server import create_app
    from fastapi.testclient import TestClient

    on = TestClient(
        create_app(
            "sqlite://",
            tokens=TOKENS,
            outbox_interval=0,
            env={"ALES_REQUIRE_SIGNATURES": "1", "ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY": "1"},
        )
    )
    off = TestClient(create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_REQUIRE_SIGNATURES": "0"}))
    assert on.post("/v1/sources", json=chain()[0], headers=T1).status_code == 403
    assert off.post("/v1/sources", json=chain()[0], headers=T1).status_code == 200
    # explicit argument beats env
    over = TestClient(create_app("sqlite://", tokens=TOKENS, outbox_interval=0, require_signatures=False,
                                 env={"ALES_REQUIRE_SIGNATURES": "1"}))
    assert over.post("/v1/sources", json=chain()[0], headers=T1).status_code == 200


# -------------------------------------------------------------------------------------- key admin
def test_key_admin_lifecycle_and_audit(client):
    key = Ed25519PrivateKey.generate()
    created = _register_key(client, key)
    assert created["tenant_id"] == "t1" and created["status"] == "active"
    assert created["public_key_b64"] == pub_b64(key)
    assert [k["key_id"] for k in client.get("/v1/admin/keys").json()["keys"]] == ["k1"]
    assert client.patch("/v1/admin/keys/k1", json={"status": "retired"}).json()["status"] == "retired"
    assert client.patch("/v1/admin/keys/k1", json={"status": "revoked"}).json()["status"] == "revoked"
    # revoked is terminal
    r = client.patch("/v1/admin/keys/k1", json={"status": "active"})
    assert r.status_code == 409
    actions = [(a, d.get("key_id")) for a, _, d in _audit_actions(client) if a.startswith("admin.")]
    assert ("admin.key.register", "k1") in actions
    assert actions.count(("admin.key.set_status", "k1")) == 2
    assert any(a == "admin.key.list" for a, _ in actions)
    assert {actor for a, actor, _ in _audit_actions(client) if a.startswith("admin.")} == {"svc-t1"}


def test_key_admin_negative_cases(client):
    key = Ed25519PrivateKey.generate()
    _register_key(client, key)
    # duplicate key_id, same tenant and other tenant (global namespace, no re-binding)
    body = {"key_id": "k1", "public_key_b64": pub_b64(key)}
    assert client.post("/v1/admin/keys", json=body).status_code == 409
    assert client.post("/v1/admin/keys", json=body, headers=T2).status_code == 409
    # malformed keys / bodies
    for bad in ("", "!!!", "AAAA", pub_b64(key)[:-4]):
        r = client.post("/v1/admin/keys", json={"key_id": "kx", "public_key_b64": bad})
        assert r.status_code in (422,), bad
    assert client.post("/v1/admin/keys", json={"key_id": "", "public_key_b64": pub_b64(key)}).status_code == 422
    assert client.post("/v1/admin/keys", json={"key_id": "k" * 200, "public_key_b64": pub_b64(key)}).status_code == 422
    assert client.post("/v1/admin/keys", json={"key_id": "k9", "public_key_b64": pub_b64(key), "x": 1}).status_code == 422
    assert client.patch("/v1/admin/keys/k1", json={"status": "bogus"}).status_code == 422
    assert client.patch("/v1/admin/keys/k1", json={}).status_code == 422
    # tenant t2 can neither see nor modify t1's key, and cannot tell it from a missing one
    assert client.patch("/v1/admin/keys/k1", json={"status": "revoked"}, headers=T2).status_code == 404
    assert client.patch("/v1/admin/keys/nope", json={"status": "revoked"}, headers=T2).status_code == 404
    assert client.get("/v1/admin/keys", headers=T2).json() == {"keys": []}
    assert client.get("/v1/admin/keys").json()["keys"][0]["status"] == "active"
    # tenant in body is forced to the token's
    r = client.post("/v1/admin/keys", json={"key_id": "k5", "tenant_id": "t2", "public_key_b64": pub_b64(key)})
    assert r.status_code == 403
    r = client.post("/v1/admin/keys", json={"key_id": "k5", "tenant_id": "t1", "public_key_b64": pub_b64(key)})
    assert r.status_code == 201 and r.json()["tenant_id"] == "t1"


def test_non_admin_cannot_manage_keys(client):
    key = Ed25519PrivateKey.generate()
    body = {"key_id": "kz", "public_key_b64": pub_b64(key)}
    for tok in ("tok-t1-read", "tok-t1-ingest", "tok-t1-revoke"):
        h = bearer(tok)
        assert client.post("/v1/admin/keys", json=body, headers=h).status_code == 403
        assert client.get("/v1/admin/keys", headers=h).status_code == 403
        assert client.patch("/v1/admin/keys/kz", json={"status": "revoked"}, headers=h).status_code == 403
    assert client.get("/v1/admin/keys").json() == {"keys": []}


def test_key_registered_before_signed_ingest_then_revoked_midstream(sclient):
    key = Ed25519PrivateKey.generate()
    _register_key(sclient, key)
    src, chunk, _ = _signed_chain(key)
    assert sclient.post("/v1/sources", json=src).status_code == 200
    sclient.patch("/v1/admin/keys/k1", json={"status": "revoked"})
    assert sclient.post("/v1/derivations", json=chunk).status_code == 403
    # an already-registered object is unaffected by later key revocation (registration time trust)
    assert sclient.get(f"/v1/lineage/{src['context_id']}").status_code == 200


def test_require_signatures_without_snapshot_key_fails_closed():
    import pytest as _pytest
    from ales_server import create_app
    from ales_server.config import ConfigError

    with _pytest.raises(ConfigError, match="ALES_SNAPSHOT_KEY"):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0, require_signatures=True)
