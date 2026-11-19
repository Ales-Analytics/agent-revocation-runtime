"""Outbox operations endpoints: dead-letter list/requeue (R11) and on-demand run; tenant isolation."""

from __future__ import annotations

from ales_core import AuditLog, InvalidationOutbox
from server_helpers import T2, chain
from sqlalchemy import select, update

ADMIN = {"Authorization": "Bearer tok-t1-admin"}
ADMIN2 = {"Authorization": "Bearer tok-t2-all"}


def _revoke_chain(client, tenant="t1", headers=None):
    src, chunk, summ = chain(tenant)
    assert client.post("/v1/sources", json=src, headers=headers).status_code == 200
    for env in (chunk, summ):
        assert client.post("/v1/derivations", json=env, headers=headers).status_code == 200
    r = client.post(
        "/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"}, headers=headers
    )
    assert r.status_code == 200


def _rows(app, tenant=None):
    with app.state.session_factory() as s:
        q = select(InvalidationOutbox).order_by(InvalidationOutbox.id)
        if tenant:
            q = q.where(InvalidationOutbox.tenant_id == tenant)
        return list(s.scalars(q))


def _kill(app, tenant, err="boom"):
    with app.state.session_factory() as s:
        s.execute(
            update(InvalidationOutbox)
            .where(InvalidationOutbox.tenant_id == tenant)
            .values(state="dead", attempts=6, last_error=err)
        )
        s.commit()


def test_dead_list_shape_and_requeue_flow(make_client):
    seen: list[str] = []
    c = make_client(outbox_handlers={"*": lambda row: seen.append(row.context_id)})
    _revoke_chain(c)
    _kill(c.app, "t1", err="ConnectionError: qdrant down")
    dead = c.get("/v1/outbox/dead", headers=ADMIN).json()["dead"]
    assert len(dead) == 3
    assert set(dead[0]) == {
        "id",
        "context_id",
        "version",
        "store_kind",
        "attempts",
        "last_error",
        "created_at",
    }
    assert dead[0]["last_error"] == "ConnectionError: qdrant down" and dead[0]["attempts"] == 6

    rid = dead[0]["id"]
    r = c.post(f"/v1/outbox/dead/{rid}/requeue", headers=ADMIN)
    assert r.status_code == 200 and r.json() == {"id": rid, "state": "pending", "attempts": 0}
    row = next(x for x in _rows(c.app) if x.id == rid)
    assert (row.state, row.attempts, row.last_error, row.lease_token) == ("pending", 0, None, None)
    assert c.post(f"/v1/outbox/dead/{rid}/requeue", headers=ADMIN).status_code == 409  # no longer dead
    assert len(c.get("/v1/outbox/dead", headers=ADMIN).json()["dead"]) == 2

    with c.app.state.session_factory() as s:
        actions = list(s.scalars(select(AuditLog).where(AuditLog.action == "admin.outbox.requeue")))
    assert (
        len(actions) == 1
        and actions[0].detail["outbox_id"] == rid
        and actions[0].detail["attempts_before"] == 6
    )

    run = c.post("/v1/outbox/run", headers=ADMIN).json()
    assert run == {"leased": 1, "done": 1, "failed": 0, "dead": 0, "lost_lease": 0}
    assert len(seen) == 1
    assert c.get("/v1/outbox/stats").json()["totals"]["done"] == 1


def test_run_reports_failures_and_dead_after_budget(make_client):
    def boom(row):
        raise RuntimeError("store unavailable")

    c = make_client(outbox_handlers={"*": boom})
    _revoke_chain(c)
    out = c.post("/v1/outbox/run", headers=ADMIN).json()
    assert out["leased"] == 3 and out["failed"] == 3 and out["done"] == 0
    assert c.post("/v1/outbox/run", headers=ADMIN).json()["leased"] == 0  # backoff: not due yet
    assert c.get("/v1/outbox/stats").json()["totals"]["pending"] == 3


def test_pagination_and_limit_validation(make_client):
    c = make_client()
    _revoke_chain(c)
    _kill(c.app, "t1")
    first = c.get("/v1/outbox/dead?limit=2", headers=ADMIN).json()["dead"]
    assert len(first) == 2
    rest = c.get(f"/v1/outbox/dead?limit=2&after_id={first[-1]['id']}", headers=ADMIN).json()["dead"]
    assert len(rest) == 1 and rest[0]["id"] > first[-1]["id"]
    assert c.get("/v1/outbox/dead?limit=0", headers=ADMIN).status_code == 422
    assert c.get("/v1/outbox/dead?limit=100000", headers=ADMIN).status_code == 422


def test_tenant_isolation(make_client):
    seen: list[str] = []
    c = make_client(outbox_handlers={"*": lambda row: seen.append(row.tenant_id)})
    _revoke_chain(c, "t1")
    _revoke_chain(c, "t2", headers=T2)
    _kill(c.app, "t1")
    _kill(c.app, "t2")
    t2_ids = [r.id for r in _rows(c.app, "t2")]
    t1_ids = [r.id for r in _rows(c.app, "t1")]

    assert {d["id"] for d in c.get("/v1/outbox/dead", headers=ADMIN).json()["dead"]} == set(t1_ids)
    assert {d["id"] for d in c.get("/v1/outbox/dead", headers=ADMIN2).json()["dead"]} == set(t2_ids)
    # t1 cannot requeue a t2 row: indistinguishable from absent, and the row is untouched
    assert c.post(f"/v1/outbox/dead/{t2_ids[0]}/requeue", headers=ADMIN).status_code == 404
    assert c.post("/v1/outbox/dead/999999/requeue", headers=ADMIN).status_code == 404
    assert all(r.state == "dead" for r in _rows(c.app, "t2"))

    # requeue both tenants' rows; t1's run processes only t1
    for i in t1_ids:
        assert c.post(f"/v1/outbox/dead/{i}/requeue", headers=ADMIN).status_code == 200
    for i in t2_ids:
        assert c.post(f"/v1/outbox/dead/{i}/requeue", headers=ADMIN2).status_code == 200
    out = c.post("/v1/outbox/run", headers=ADMIN).json()
    assert out["leased"] == len(t1_ids) and set(seen) == {"t1"}
    assert all(r.state == "pending" for r in _rows(c.app, "t2"))
    assert c.post("/v1/outbox/run", headers=ADMIN2).json()["leased"] == len(t2_ids)
    assert set(seen) == {"t1", "t2"}
