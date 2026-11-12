"""Concurrent registration / revocation-submission races (stress suite; run with ``pytest -q stress``).

SQLite serialises writers, so some interleavings only really occur on the Postgres param (CI).
All races are exercised against a FRESH tenant so that first-write tenant creation is raced too.
"""

from __future__ import annotations

import uuid

from ales_sdk import new_derivative, new_source
from sqlalchemy import func, select
from stress_helpers import authorize, make_app, post_ok, revocation_body, run_threads, tclient

N = 8


def _post(app, path, body, tenant="t1"):
    tc = tclient(app, tenant)
    return tc.post(path, json=body)


def test_duplicate_source_same_digest_is_idempotent(db_url, engine):
    app = make_app(db_url)
    src = new_source("t1", "doc", b"same", "kb")
    results, errors = run_threads([lambda: _post(app, "/v1/sources", src) for _ in range(N)])
    assert not errors, errors
    assert [r.status_code for r in results] == [200] * N, [(r.status_code, r.text) for r in results]
    from ales_core import ContextObject
    from sqlalchemy.orm import Session

    with Session(engine) as s:
        assert s.scalar(select(func.count()).select_from(ContextObject)) == 1


def test_duplicate_source_different_digest_exactly_one_wins(db_url):
    app = make_app(db_url)
    cid = str(uuid.uuid4())
    bodies = [new_source("t1", "doc", f"content-{i}".encode(), "kb", context_id=cid) for i in range(N)]
    results, errors = run_threads([lambda b=b: _post(app, "/v1/sources", b) for b in bodies])
    assert not errors, errors
    codes = sorted(r.status_code for r in results)
    assert codes == [200] + [409] * (N - 1), codes
    assert all(r.json()["error"] == "duplicate_context" for r in results if r.status_code == 409)


def test_concurrent_derivations_under_same_parent(db_url, engine):
    app = make_app(db_url)
    main = tclient(app)
    src = new_source("t1", "doc", b"parent", "kb")
    post_ok(main, "/v1/sources", src)
    kids = [new_derivative("chunk", [src], "t1", f"chunk-{i}", f"c{i}".encode()) for i in range(N)]
    results, errors = run_threads([lambda k=k: _post(app, "/v1/derivations", k) for k in kids])
    assert not errors, errors
    assert [r.status_code for r in results] == [200] * N, [(r.status_code, r.text) for r in results]
    lin = main.get(f"/v1/lineage/{src['context_id']}").json()
    assert sorted(d["context_id"] for d in lin["descendants"]) == sorted(k["context_id"] for k in kids)


def test_same_derivation_concurrently_is_idempotent(db_url):
    app = make_app(db_url)
    main = tclient(app)
    src = new_source("t1", "doc", b"parent", "kb")
    post_ok(main, "/v1/sources", src)
    kid = new_derivative("chunk", [src], "t1", "chunk", b"c")
    results, errors = run_threads([lambda: _post(app, "/v1/derivations", kid) for _ in range(N)])
    assert not errors, errors
    assert [r.status_code for r in results] == [200] * N, [(r.status_code, r.text) for r in results]


def test_same_event_id_concurrently_bumps_epoch_once(db_url, engine):
    app = make_app(db_url)
    main = tclient(app)
    src = new_source("t1", "doc", b"x", "kb")
    post_ok(main, "/v1/sources", src)
    body = revocation_body("t1", src["context_id"], event_id=str(uuid.uuid4()))
    results, errors = run_threads([lambda: _post(app, "/v1/revocations", body) for _ in range(N)])
    assert not errors, errors
    assert [r.status_code for r in results] == [200] * N, [(r.status_code, r.text) for r in results]
    assert {r.json()["revocation_epoch"] for r in results} == {1}
    from ales_core import RevocationEventRow, Tenant
    from sqlalchemy.orm import Session

    with Session(engine) as s:
        assert s.get(Tenant, "t1").revocation_epoch == 1
        assert s.scalar(select(func.count()).select_from(RevocationEventRow)) == 1
    assert authorize(main, "t1", src["context_id"]) != "ALLOW"
