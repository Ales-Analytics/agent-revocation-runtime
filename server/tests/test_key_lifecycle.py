"""Issuer-key lifecycle as an operator lives it: rotation, terminal revocation, outage, recovery.

Pins one semantic explicitly: retiring or revoking an INGRESS key only stops that key vouching for NEW
objects/events. Objects already ingested under it stay registered and usable (their authenticity was
verified at ingest time); revoking *data* is done with revocation events, not key status.
"""

from __future__ import annotations

import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from server_helpers import authorize_body, chain, pub_b64, sign_env, sign_event


@pytest.fixture
def sclient(make_client):
    return make_client(require_signatures=True)


def _register(c, key, key_id):
    r = c.post("/v1/admin/keys", json={"key_id": key_id, "public_key_b64": pub_b64(key)})
    assert r.status_code == 201, r.text


def _set(c, key_id, status):
    return c.patch(f"/v1/admin/keys/{key_id}", json={"status": status})


def _signed(key, key_id, tenant="t1"):
    src, chunk, summ = chain(tenant)
    return [sign_env(e, key, key_id) for e in (src, chunk, summ)]


def _allowed(c, context_id):
    r = c.post("/v1/authorize", json=authorize_body("t1", context_id))
    assert r.status_code == 200, r.text
    return r.json()["decision"]


def test_rotation_old_objects_stay_usable_new_ingests_follow_the_active_key(sclient):
    k1, k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    _register(sclient, k1, "k1")
    src_old, chunk_old, _ = _signed(k1, "k1")
    assert sclient.post("/v1/sources", json=src_old).status_code == 200
    assert sclient.post("/v1/derivations", json=chunk_old).status_code == 200
    # rotation: register k2, retire k1
    _register(sclient, k2, "k2")
    r = _set(sclient, "k1", "retired")
    assert r.status_code == 200 and r.json()["status"] == "retired"
    # previously ingested objects are NOT retroactively invalidated
    assert sclient.get(f"/v1/lineage/{chunk_old['context_id']}").status_code == 200
    assert _allowed(sclient, chunk_old["context_id"]) == "ALLOW"
    # new ingest under the retired key is rejected key_not_active ...
    src_late = _signed(k1, "k1")[0]
    r = sclient.post("/v1/sources", json=src_late)
    assert r.status_code == 403 and r.json() == {"detail": "key_not_active"}
    assert sclient.get(f"/v1/lineage/{src_late['context_id']}").status_code == 404
    # ... and under the new key is accepted
    src_new, chunk_new, _ = _signed(k2, "k2")
    assert sclient.post("/v1/sources", json=src_new).status_code == 200
    assert sclient.post("/v1/derivations", json=chunk_new).status_code == 200
    assert _allowed(sclient, chunk_new["context_id"]) == "ALLOW"
    keys = {k["key_id"]: k["status"] for k in sclient.get("/v1/admin/keys").json()["keys"]}
    assert keys == {"k1": "retired", "k2": "active"}


def test_revoking_an_ingress_key_does_not_retroactively_invalidate_ingested_objects(sclient):
    key = Ed25519PrivateKey.generate()
    _register(sclient, key, "k1")
    src, chunk, _ = _signed(key, "k1")
    assert sclient.post("/v1/sources", json=src).status_code == 200
    assert sclient.post("/v1/derivations", json=chunk).status_code == 200
    assert _set(sclient, "k1", "revoked").status_code == 200
    assert _allowed(sclient, chunk["context_id"]) == "ALLOW"
    assert sclient.get(f"/v1/lineage/{src['context_id']}").status_code == 200


def test_revoked_is_terminal_and_retired_cannot_return_to_active(sclient):
    key = Ed25519PrivateKey.generate()
    _register(sclient, key, "k1")
    assert _set(sclient, "k1", "revoked").status_code == 200
    for target in ("active", "retired"):
        r = _set(sclient, "k1", target)
        assert r.status_code == 409 and "illegal key status transition" in r.json()["detail"]
    key2 = Ed25519PrivateKey.generate()
    _register(sclient, key2, "k2")
    assert _set(sclient, "k2", "retired").status_code == 200
    assert _set(sclient, "k2", "active").status_code == 409
    assert _set(sclient, "k2", "revoked").status_code == 200
    # the key_id cannot be re-registered with fresh material either
    r = sclient.post(
        "/v1/admin/keys", json={"key_id": "k1", "public_key_b64": pub_b64(Ed25519PrivateKey.generate())}
    )
    assert r.status_code == 409


def test_key_outage_blocks_ingest_only_then_recovery_with_a_new_key(sclient):
    key = Ed25519PrivateKey.generate()
    _register(sclient, key, "k1")
    src, chunk, _ = _signed(key, "k1")
    assert sclient.post("/v1/sources", json=src).status_code == 200
    assert sclient.post("/v1/derivations", json=chunk).status_code == 200
    assert _set(sclient, "k1", "revoked").status_code == 200  # the only key: outage

    # every ingest path is refused 403 ...
    src2, chunk2, _ = _signed(key, "k1")
    for path, body in (("/v1/sources", src2), ("/v1/derivations", chunk2)):
        r = sclient.post(path, json=body)
        assert r.status_code == 403 and r.json() == {"detail": "key_not_active"}, path
    ev = sign_event(
        {
            "event_id": str(uuid.uuid4()),
            "tenant_id": "t1",
            "source_id": src["context_id"],
            "reason": "deleted",
            "effective_at": "2026-01-01T00:00:00Z",
        },
        key,
        "k1",
    )
    r = sclient.post("/v1/revocations", json=ev)
    assert r.status_code == 403 and r.json() == {"detail": "key_not_active"}
    # ... while authorize / lineage / snapshot / admin reads are unaffected
    assert _allowed(sclient, chunk["context_id"]) == "ALLOW"
    assert sclient.get(f"/v1/lineage/{chunk['context_id']}").status_code == 200
    assert sclient.get("/v1/snapshot").status_code == 200
    assert sclient.get("/v1/admin/keys").status_code == 200

    # recovery: register key3 -> ingest and signed revocations resume
    key3 = Ed25519PrivateKey.generate()
    _register(sclient, key3, "k3")
    src3, chunk3, _ = _signed(key3, "k3")
    assert sclient.post("/v1/sources", json=src3).status_code == 200
    assert sclient.post("/v1/derivations", json=chunk3).status_code == 200
    ev3 = sign_event(
        {
            "event_id": str(uuid.uuid4()),
            "tenant_id": "t1",
            "source_id": src["context_id"],
            "reason": "deleted",
            "effective_at": "2026-01-01T00:00:00Z",
        },
        key3,
        "k3",
    )
    r = sclient.post("/v1/revocations", json=ev3)
    assert r.status_code == 200 and r.json()["revocation_epoch"] == 1
    # the revoked source's lineage is now denied; the independent new chain is untouched
    assert _allowed(sclient, chunk["context_id"]) != "ALLOW"
    assert _allowed(sclient, chunk3["context_id"]) == "ALLOW"
