"""Signed policy snapshots (verified with the SDK's own verifier) and the tamper-evident audit ledger."""

from __future__ import annotations

import base64
import itertools
import json
import time

import pytest
from ales_core import AuditLog, audit_head
from ales_sdk.errors import SnapshotError
from ales_sdk.snapshot import canonical_bytes as sdk_canonical
from ales_sdk.snapshot import load_public_keys, verify_snapshot
from ales_server import create_app
from ales_server.config import ConfigError
from ales_server.snapshot import canonical_bytes as server_canonical
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from server_helpers import T1, T2, TOKENS, authorize_body, bearer, chain, pub_b64, seed_b64
from sqlalchemy import select, update


def _verify(snap, pub, tenant="t1", **kw):
    return verify_snapshot(
        snap, keys=load_public_keys(pub), tenant_id=tenant, received_at=0.0, wall_now=kw.pop("wall_now", time.time()), **kw
    )


@pytest.fixture
def pub(client):
    return client.get("/v1/snapshot/public_key").json()["public_key_b64"]


# --------------------------------------------------------------------------------------- snapshot
def test_snapshot_verifies_with_sdk(client, pub):
    snap = client.get("/v1/snapshot").json()
    assert set(snap) == {"tenant_id", "revocation_epoch", "policy_version", "issued_at", "lease_seconds",
                         "signature", "key_id"}
    assert isinstance(snap["revocation_epoch"], int) and isinstance(snap["lease_seconds"], int)
    v = _verify(snap, pub)
    assert v.tenant_id == "t1" and v.revocation_epoch == 0 and v.lease_seconds == 60
    assert v.effective_lease > 55  # freshly issued: nearly the whole lease
    assert snap["issued_at"].endswith("+00:00")
    assert client.get("/v1/snapshot").headers["cache-control"] == "no-store"


def test_snapshot_key_id_selects_key_from_mapping(client, pub):
    snap = client.get("/v1/snapshot").json()
    keys = load_public_keys({snap["key_id"]: pub})
    assert verify_snapshot(snap, keys=keys, tenant_id="t1", received_at=0, wall_now=time.time())
    other = load_public_keys({"some-other": pub})
    with pytest.raises(SnapshotError) as ei:
        verify_snapshot(snap, keys=other, tenant_id="t1", received_at=0, wall_now=time.time())
    assert ei.value.reason == "unknown_key_id"


def test_server_and_sdk_canonical_bytes_agree(client):
    snap = client.get("/v1/snapshot").json()
    assert server_canonical(snap) == sdk_canonical(snap)
    assert b"signature" not in server_canonical(snap) and b"key_id" not in server_canonical(snap)
    expected = json.dumps({k: v for k, v in snap.items() if k not in ("signature", "key_id")},
                          sort_keys=True, separators=(",", ":")).encode()
    assert server_canonical(snap) == expected


def test_tampered_snapshot_fails_client_side(client, pub):
    snap = client.get("/v1/snapshot").json()
    for field, value in (("revocation_epoch", 99), ("lease_seconds", 86400), ("tenant_id", "t2"),
                         ("policy_version", "evil"), ("issued_at", "2030-01-01T00:00:00+00:00")):
        with pytest.raises(SnapshotError) as ei:
            _verify({**snap, field: value}, pub, tenant="t1" if field != "tenant_id" else "t2")
        assert ei.value.reason == "bad_signature", field
    sig = bytearray(base64.b64decode(snap["signature"]))
    sig[0] ^= 1
    with pytest.raises(SnapshotError) as ei:
        _verify({**snap, "signature": base64.b64encode(bytes(sig)).decode()}, pub)
    assert ei.value.reason == "bad_signature"
    with pytest.raises(SnapshotError):
        _verify({k: v for k, v in snap.items() if k != "signature"}, pub)
    # extra, unsigned members are covered by the signature too (future-proofing)
    with pytest.raises(SnapshotError):
        _verify({**snap, "extra": 1}, pub)


def test_snapshot_signed_by_other_key_fails(client):
    snap = client.get("/v1/snapshot").json()
    other = pub_b64(Ed25519PrivateKey.generate())
    with pytest.raises(SnapshotError) as ei:
        _verify(snap, other)
    assert ei.value.reason == "bad_signature"


def test_snapshot_for_other_tenant_fails_client_side(client, pub):
    snap = client.get("/v1/snapshot").json()
    with pytest.raises(SnapshotError) as ei:
        _verify(snap, pub, tenant="t2")
    assert ei.value.reason == "tenant_mismatch"


def test_snapshot_expired_when_replayed_later(client, pub):
    snap = client.get("/v1/snapshot").json()
    with pytest.raises(SnapshotError) as ei:
        _verify(snap, pub, wall_now=time.time() + 3600)
    assert ei.value.reason == "expired"


def test_snapshot_epoch_tracks_revocations_and_is_per_tenant(client):
    src = chain()[0]
    client.post("/v1/sources", json=src)
    assert client.get("/v1/snapshot").json()["revocation_epoch"] == 0
    client.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"})
    client.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "acl_changed"})
    assert client.get("/v1/snapshot").json()["revocation_epoch"] == 2
    t2 = client.get("/v1/snapshot", headers=T2).json()
    assert t2["tenant_id"] == "t2" and t2["revocation_epoch"] == 0


def test_snapshot_policy_version_matches_decisions(client):
    src = chain()[0]
    client.post("/v1/sources", json=src)
    d = client.post("/v1/authorize", json=authorize_body("t1", src["context_id"])).json()
    assert client.get("/v1/snapshot").json()["policy_version"] == d["policy_version"]


def test_snapshot_lease_configuration(make_client):
    c = make_client(snapshot_lease=17)
    assert c.get("/v1/snapshot").json()["lease_seconds"] == 17
    c2 = TestClient(create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_SNAPSHOT_LEASE": "42"}))
    assert c2.get("/v1/snapshot", headers=T1).json()["lease_seconds"] == 42
    for bad in ("0", "-5", "abc", "1.5"):
        with pytest.raises(ConfigError):
            create_app("sqlite://", tokens=TOKENS, env={"ALES_SNAPSHOT_LEASE": bad})


def test_configured_snapshot_key_is_stable_across_restarts():
    key = Ed25519PrivateKey.generate()
    seed = seed_b64(key)
    out = []
    for _ in range(2):
        c = TestClient(create_app("sqlite://", tokens=TOKENS, outbox_interval=0,
                                  env={"ALES_SNAPSHOT_KEY": seed}))
        pk = c.get("/v1/snapshot/public_key", headers=T1).json()
        assert pk["ephemeral"] is False and pk["public_key_b64"] == pub_b64(key)
        out.append(c.get("/v1/snapshot", headers=T1).json())
    for snap in out:
        _verify(snap, pub_b64(key))
    # also accepted as an argument
    c = TestClient(create_app("sqlite://", tokens=TOKENS, outbox_interval=0, snapshot_private_key=key))
    assert c.get("/v1/snapshot/public_key", headers=T1).json()["public_key_b64"] == pub_b64(key)


def test_ephemeral_key_differs_per_app_and_is_flagged(caplog):
    with caplog.at_level("WARNING", logger="ales.server.snapshot"):
        a = TestClient(create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={}))
    assert any("EPHEMERAL" in r.getMessage() for r in caplog.records)
    b = TestClient(create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={}))
    pa, pb = (x.get("/v1/snapshot/public_key", headers=T1).json() for x in (a, b))
    assert pa["ephemeral"] is True and pa["public_key_b64"] != pb["public_key_b64"]


@pytest.mark.parametrize("bad", ["not-base64!!", "AAAA", base64.b64encode(b"x" * 31).decode(),
                                 base64.b64encode(b"x" * 33).decode()])
def test_malformed_snapshot_key_is_a_startup_error_not_a_silent_ephemeral(bad):
    with pytest.raises(ConfigError):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_SNAPSHOT_KEY": bad})


def test_snapshot_requires_read_and_binds_tenant(client):
    assert client.get("/v1/snapshot", headers=bearer("tok-t1-ingest")).status_code == 403
    assert client.get("/v1/snapshot/public_key", headers=bearer("tok-t1-ingest")).status_code == 403
    assert client.get("/v1/snapshot", headers={"X-Tenant-Id": "t2"}).status_code == 403


# ------------------------------------------------------------------------------------------ audit
def _rows(c, tenant="t1"):
    with c.app.state.session_factory() as s:
        return list(s.scalars(select(AuditLog).where(AuditLog.tenant_id == tenant).order_by(AuditLog.seq)))


def test_decisions_registrations_and_revocations_are_audited_with_authenticated_actor(client):
    src, chunk, summ = chain()
    for env, path in ((src, "/v1/sources"), (chunk, "/v1/derivations"), (summ, "/v1/derivations")):
        client.post(path, json=env)
    body = authorize_body("t1", summ["context_id"])
    body["principal"] = {"type": "user", "id": "someone-else"}  # request-claimed identity is NOT the actor
    d = client.post("/v1/authorize", json=body).json()
    client.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted", "actor": "claimed-admin"})
    d2 = client.post("/v1/authorize", json=body).json()
    assert d["decision"] == "ALLOW" and d2["decision"] == "DENY"

    rows = _rows(client)
    by_action = {}
    for r in rows:
        by_action.setdefault(r.action, []).append(r)
    assert len(by_action["source.register"]) == 1 and len(by_action["derivation.register"]) == 2
    assert {r.actor for r in rows} == {"svc-t1"}
    decisions = by_action["decision.authorize"]
    assert [r.detail["decision"] for r in decisions] == ["ALLOW", "DENY"]
    assert decisions[0].detail["trace_id"] == d["trace_id"]
    assert decisions[0].detail["principal"] == {"type": "user", "id": "someone-else"}
    rev = by_action["revocation.accept"][0]
    assert rev.actor == "svc-t1" and rev.detail["claimed_actor"] == "claimed-admin"
    assert rev.detail["revocation_epoch"] == 1
    reg = by_action["source.register"][0].detail
    assert reg["context_id"] == src["context_id"] and reg["kind"] == "source"


def test_no_document_content_in_ledger(client):
    src, chunk, summ = chain()
    for env, path in ((src, "/v1/sources"), (chunk, "/v1/derivations"), (summ, "/v1/derivations")):
        client.post(path, json=env)
    client.post("/v1/authorize", json=authorize_body("t1", summ["context_id"]))
    blob = json.dumps([r.detail for r in _rows(client)])
    assert "secret" not in blob and src["content_digest"] not in blob


def test_audit_chain_verifies_and_is_per_tenant(client):
    src, chunk, summ = chain()
    for env, path in ((src, "/v1/sources"), (chunk, "/v1/derivations"), (summ, "/v1/derivations")):
        client.post(path, json=env)
    client.post("/v1/authorize", json=authorize_body("t1", summ["context_id"]))
    r = client.get("/v1/audit/verify")
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["first_bad_seq"] is None
    assert r.json()["records_checked"] >= 4
    # hash chain is real: each record links to the previous one
    rows = _rows(client)
    assert rows[0].prev_hash == "0" * 64
    for a, b in itertools.pairwise(rows):
        assert b.prev_hash == a.hash
    with client.app.state.session_factory() as s:
        assert audit_head(s, "t1")[1] == rows[-1].hash


def test_audit_verify_detects_tampering(client):
    src, chunk, summ = chain()
    for env, path in ((src, "/v1/sources"), (chunk, "/v1/derivations"), (summ, "/v1/derivations")):
        client.post(path, json=env)
    client.post("/v1/authorize", json=authorize_body("t1", summ["context_id"]))
    rows = _rows(client)
    victim = rows[2]
    with client.app.state.session_factory() as s:
        s.execute(update(AuditLog).where(AuditLog.seq == victim.seq).values(actor="mallory"))
        s.commit()
    r = client.get("/v1/audit/verify")
    assert r.status_code == 200
    assert r.json()["ok"] is False and r.json()["first_bad_seq"] == victim.seq


def test_audit_verify_detects_deleted_record(client):
    src, chunk, _ = chain()
    client.post("/v1/sources", json=src)
    client.post("/v1/derivations", json=chunk)
    client.post("/v1/authorize", json=authorize_body("t1", chunk["context_id"]))
    rows = _rows(client)
    with client.app.state.session_factory() as s:
        s.delete(s.get(AuditLog, rows[1].seq))
        s.commit()
    r = client.get("/v1/audit/verify").json()
    assert r["ok"] is False and r["first_bad_seq"] == rows[2].seq


def test_audit_verify_is_scoped_to_callers_tenant(client):
    for tok in (T1, T2):
        t = "t1" if tok is T1 else "t2"
        client.post("/v1/sources", json=chain(t)[0], headers=tok)
    t2_rows = _rows(client, "t2")
    with client.app.state.session_factory() as s:
        s.execute(update(AuditLog).where(AuditLog.seq == t2_rows[0].seq).values(actor="mallory"))
        s.commit()
    assert client.get("/v1/audit/verify").json()["ok"] is True  # t1 chain intact, t2 damage not reported to t1
    assert client.get("/v1/audit/verify", headers=T2).json()["first_bad_seq"] == t2_rows[0].seq


def test_audit_verify_requires_admin(client):
    for tok in ("tok-t1-read", "tok-t1-ingest", "tok-t1-revoke"):
        assert client.get("/v1/audit/verify", headers=bearer(tok)).status_code == 403
    assert client.get("/v1/audit/verify", headers=bearer("tok-t1-admin")).status_code == 200


def test_audit_verify_call_is_itself_audited(client):
    client.get("/v1/audit/verify")
    assert [r.action for r in _rows(client)] == ["admin.audit.verify"]


def test_oversized_identifiers_are_rejected_before_deciding(client):
    body = authorize_body("t1", "x")
    body["purpose"] = "p" * 600
    r = client.post("/v1/authorize", json=body)
    assert r.status_code == 422
    assert [x for x in _rows(client) if x.action == "decision.authorize"] == []


def test_authorize_fails_closed_when_the_ledger_cannot_record(client, monkeypatch):
    src = chain()[0]
    client.post("/v1/sources", json=src)

    def boom(*a, **k):
        raise RuntimeError("ledger down")

    monkeypatch.setattr("ales_server.routes.record_decision", boom)
    c = TestClient(client.app, raise_server_exceptions=False, headers=dict(T1))
    r = c.post("/v1/authorize", json=authorize_body("t1", src["context_id"]))
    assert r.status_code == 500 and "ALLOW" not in r.text


def test_verify_scratch_chain_is_audited_and_verifiable(client):
    assert client.post("/v1/verify", json={"tenant_id": "t1"}).json()["passed"] is True
    scratch = _rows(client, "t1:verify")
    assert {r.actor for r in scratch} == {"svc-t1"} and len(scratch) >= 3
    assert client.get("/v1/audit/verify").json()["ok"] is True
    with client.app.state.session_factory() as s:
        s.execute(update(AuditLog).where(AuditLog.seq == scratch[0].seq).values(actor="x"))
        s.commit()
    r = client.get("/v1/audit/verify").json()
    assert r["ok"] is False and r["first_bad_seq"] == scratch[0].seq
