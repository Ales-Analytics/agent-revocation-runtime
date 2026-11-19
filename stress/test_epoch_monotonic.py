"""Epochs never cross tenants and are gap-free; the audit chain survives concurrent writers.

Stress suite (``pytest -q stress``). On Postgres the audit append race is serialised by the tenant
row lock; on SQLite by the database write lock (see ales_core.db.lock_tenant).
"""

from __future__ import annotations

from ales_core import RevocationEventRow, Tenant, verify_chain
from ales_core.audit import head
from ales_sdk import new_source
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from stress_helpers import authorize, make_app, post_ok, revocation_body, run_threads, tclient

PER_TENANT = 10


def test_concurrent_revocations_two_tenants(db_url, engine):
    app = make_app(db_url)
    sources: dict[str, list[dict]] = {}
    for t in ("t1", "t2"):
        tc = tclient(app, t)
        sources[t] = [new_source(t, f"doc-{i}", f"x{i}".encode(), "kb") for i in range(PER_TENANT)]
        for s in sources[t]:
            post_ok(tc, "/v1/sources", s)

    def revoke(t: str, src: dict):
        tc = tclient(app, t)
        r = tc.post("/v1/revocations", json=revocation_body(t, src["context_id"]))
        assert r.status_code == 200, (r.status_code, r.text)
        return t, r.json()["revocation_epoch"]

    def read(t: str, src: dict):
        # concurrent decisions append to the same audit chains
        return t, authorize(tclient(app, t), t, src["context_id"])

    fns = [lambda t=t, s=s: revoke(t, s) for t in sources for s in sources[t]]
    fns += [lambda t=t, s=s: read(t, s) for t in sources for s in sources[t][:5]]
    results, errors = run_threads(fns)
    assert not errors, errors

    epochs: dict[str, list[int]] = {"t1": [], "t2": []}
    for (t, e), kind in zip(results, ["rev"] * (2 * PER_TENANT) + ["read"] * 10, strict=True):
        if kind == "rev":
            epochs[t].append(e)
    for t in ("t1", "t2"):
        assert sorted(epochs[t]) == list(range(1, PER_TENANT + 1)), (t, sorted(epochs[t]))

    with Session(engine) as s:
        for t in ("t1", "t2"):
            assert s.get(Tenant, t).revocation_epoch == PER_TENANT
            n = s.scalar(
                select(func.count()).select_from(RevocationEventRow).where(RevocationEventRow.tenant_id == t)
            )
            assert n == PER_TENANT
        ok, bad = verify_chain(s)
        assert ok, f"audit chain broken at seq {bad}"
        for t in ("t1", "t2"):
            assert head(s, t) is not None
    # everything revoked is now denied
    for t, srcs in sources.items():
        tc = tclient(app, t)
        assert all(authorize(tc, t, s["context_id"]) != "ALLOW" for s in srcs)


def test_concurrent_audit_appends_keep_chain_valid(db_url, engine):
    """Many concurrent decisions for ONE tenant: no 500s, no forked chain."""
    app = make_app(db_url)
    tc = tclient(app)
    src = new_source("t1", "doc", b"x", "kb")
    post_ok(tc, "/v1/sources", src)
    results, errors = run_threads(
        [lambda: authorize(tclient(app), "t1", src["context_id"]) for _ in range(24)]
    )
    assert not errors, errors
    assert set(results) == {"ALLOW"}
    with Session(engine) as s:
        ok, bad = verify_chain(s, "t1")
        assert ok, bad
