"""Server correctness ledger: policy-aware snapshots, activation epoch bump, reconcile, migration lock."""

from __future__ import annotations

import threading

from ales_core import AuditLog
from ales_server.migrate import run_migrations_locked
from server_helpers import chain
from sqlalchemy import create_engine, select

ADMIN = {"Authorization": "Bearer tok-t1-admin"}


def _pol(version, pid="pol"):
    return {"policy_id": pid, "version": version, "rules": [], "default_action": "allow"}


def _activate(c, version):
    assert c.post("/v1/policies", json=_pol(version)).status_code == 201
    assert c.post(f"/v1/policies/pol/versions/{version}/activate").status_code == 200


def test_snapshot_signs_active_policy_version(client):
    assert client.get("/v1/snapshot").json()["policy_version"] == "p0"
    _activate(client, 1)
    assert client.get("/v1/snapshot").json()["policy_version"] == "pol@1"
    _activate(client, 2)
    assert client.get("/v1/snapshot").json()["policy_version"] == "pol@2"


def test_activation_bumps_epoch_and_audits(client):
    e0 = client.get("/v1/snapshot").json()["revocation_epoch"]
    _activate(client, 1)
    e1 = client.get("/v1/snapshot").json()["revocation_epoch"]
    _activate(client, 2)
    e2 = client.get("/v1/snapshot").json()["revocation_epoch"]
    assert e1 == e0 + 1 and e2 == e1 + 1
    with client.app.state.session_factory() as s:
        actions = [a.action for a in s.scalars(select(AuditLog).where(AuditLog.tenant_id == "t1"))]
    assert actions.count("policy.epoch_bump") == 2
    # failed activation does not bump
    assert client.post("/v1/policies/pol/versions/9/activate").status_code == 404
    assert client.get("/v1/snapshot").json()["revocation_epoch"] == e2


def test_reconcile_reports_tombstoned_and_untracked(client):
    src, chunk, _ = chain("t1")
    assert client.post("/v1/sources", json=src).status_code == 200
    assert client.post("/v1/derivations", json=chunk).status_code == 200
    ids = [src["context_id"], chunk["context_id"], "ghost-id"]
    r = client.post("/v1/outbox/reconcile", json={"store_kind": "chunk", "known_ids": ids}).json()
    assert r["untracked"] == ["ghost-id"] and r["tombstoned"] == [] and len(r["ok"]) == 2
    assert (
        client.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"}).status_code
        == 200
    )
    r = client.post("/v1/outbox/reconcile", json={"store_kind": "chunk", "known_ids": ids}).json()
    assert {t["context_id"] for t in r["tombstoned"]} == {src["context_id"], chunk["context_id"]}
    assert r["untracked"] == ["ghost-id"]


def test_reconcile_is_tenant_scoped_and_admin_only(client):
    src, _, _ = chain("t1")
    client.post("/v1/sources", json=src)
    body = {"store_kind": "chunk", "known_ids": [src["context_id"]]}
    t2 = {"Authorization": "Bearer tok-t2-all"}
    assert client.post("/v1/outbox/reconcile", json=body, headers=t2).json()["untracked"] == [
        src["context_id"]
    ]
    read = {"Authorization": "Bearer tok-t1-read"}
    assert client.post("/v1/outbox/reconcile", json=body, headers=read).status_code == 403


def test_locked_migrations_concurrent_sqlite_file(tmp_path):
    # file-backed SQLite: no advisory lock (no-op), but concurrent callers must still converge
    eng = create_engine(f"sqlite:///{tmp_path / 'm.db'}", connect_args={"timeout": 30})
    errs: list[BaseException] = []

    def go():
        try:
            run_migrations_locked(eng)
        except Exception as exc:  # noqa: BLE001  # pragma: no cover
            errs.append(exc)

    ts = [threading.Thread(target=go) for _ in range(2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errs, errs
    run_migrations_locked(eng)  # idempotent
    from ales_core.migrations import current_revision, head_revision

    assert current_revision(eng) == head_revision()
    # NOTE: the Postgres advisory-lock path is exercised by the Docker/Postgres smoke, not in unit tests.


def test_verify_selftest_uses_unrestricted_scope_and_passes(client):
    import inspect

    from ales_server import routes

    src = inspect.getsource(routes._envelope)
    assert '"principal_scope": []' not in src and '"purpose_scope": []' not in src
    body = client.post("/v1/verify", json={"tenant_id": "t1"}).json()
    assert body["passed"] is True, body
