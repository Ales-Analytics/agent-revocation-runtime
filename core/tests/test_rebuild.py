from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta

import pytest
from ales_core import (
    AuditLog,
    ContextObject,
    Decision,
    DerivationEdge,
    InvalidEnvelope,
    ReasonCode,
    RebuildError,
    RebuildInput,
    RebuildJobRow,
    RebuildOutput,
    RebuildRunner,
    RevocationEngine,
    RevocationEvent,
    TransformationRow,
    authorize,
    enqueue_rebuild,
    get_transformation,
    list_transformations,
    plan_rebuild,
    register_transformation,
)
from core_fixtures import NOW, TENANT, make_env, req
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

OTHER = "tenant-b"


@pytest.fixture
def factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)


class Store:
    """Integrator-side content store + deterministic 'uppercase' transformation."""

    def __init__(self):
        self.blobs: dict[str, bytes] = {}
        self.calls = 0

    def put(self, data: bytes) -> str:
        d = "sha256:" + hashlib.sha256(data).hexdigest()
        self.blobs[d] = data
        return d

    def upper(self, inputs: list[RebuildInput]) -> RebuildOutput:
        self.calls += 1
        joined = b"|".join(self.blobs[i.content_digest] for i in inputs)
        return RebuildOutput(self.put(joined.upper()))


def _register(session, tid="upper", idempotent=True, out="chunk", ins=("source",)):
    return register_transformation(
        session, TENANT, tid, "1", list(ins), out, f"impl://{tid}", idempotent, actor="admin", at=NOW
    )


def _world(graph, session, store):
    """source v1 -> chunk (upper) -> summary (upper2); then source v2 registered and v1 superseded."""
    src = make_env("source", version="v1")
    graph.register_source(src)
    _register(session, "upper")
    _register(session, "upper2", out="summary", ins=("chunk",))
    chunk = make_env("chunk", [(src.context_id, "v1")])
    summ = make_env("summary", [(chunk.context_id, "v1")])
    store.blobs[src.content_digest] = b"hello"
    graph.register_derivation(chunk, transformation=("upper", "1"))
    graph.register_derivation(summ, transformation=("upper2", "1"))
    session.commit()
    return src, chunk, summ


def _supersede(graph, session, src):
    v2 = make_env("source", context_id=src.context_id, version="v2", valid_from=NOW - timedelta(days=1))
    graph.register_source(v2)
    RevocationEngine().accept(
        session,
        RevocationEvent(
            event_id=str(uuid.uuid4()), tenant_id=TENANT, source_id=src.context_id, source_version="v1",
            reason="version_superseded", effective_at=NOW,
        ),
        now=NOW,
    )
    return v2


def test_register_transformation_is_immutable_and_audited(session):
    row = _register(session)
    assert (row.transformation_id, row.version, row.idempotent) == ("upper", "1", True)
    assert _register(session).id == row.id  # identical re-registration
    with pytest.raises(RebuildError):
        register_transformation(session, TENANT, "upper", "1", ["source"], "chunk", "impl://other", True, actor="a")
    for bad in (
        {"input_kinds": [], "output_kind": "chunk"},
        {"input_kinds": ["nope"], "output_kind": "chunk"},
        {"input_kinds": ["source"], "output_kind": "source"},
    ):
        with pytest.raises(RebuildError):
            register_transformation(session, TENANT, "x", "1", bad["input_kinds"], bad["output_kind"], "r", True, actor="a")
    assert [t.transformation_id for t in list_transformations(session, TENANT)] == ["upper"]
    assert get_transformation(session, OTHER, "upper", "1") is None  # per-tenant registry
    assert session.scalars(select(AuditLog).where(AuditLog.action == "transformation.register")).all()


def test_derivation_tag_requires_registered_transformation(graph, session):
    src = make_env("source")
    graph.register_source(src)
    chunk = make_env("chunk", [(src.context_id, "v1")])
    with pytest.raises(InvalidEnvelope):
        graph.register_derivation(chunk, transformation=("ghost", "1"))
    _register(session)
    row = graph.register_derivation(chunk, transformation=("upper", "1"))
    assert (row.transformation_id, row.transformation_version) == ("upper", "1")
    # set-once tagging of an already registered derivative
    other = make_env("chunk", [(src.context_id, "v1")])
    graph.register_derivation(other)
    graph.tag_transformation(TENANT, other.context_id, "v1", ("upper", "1"))
    graph.tag_transformation(TENANT, other.context_id, "v1", ("upper", "1"))  # no-op
    _register(session, "upper2")
    with pytest.raises(Exception, match="already tagged"):
        graph.tag_transformation(TENANT, other.context_id, "v1", ("upper2", "1"))


def test_plan_enqueue_run_rebuilds_as_new_derivation_and_cascades(graph, session, factory):
    store = Store()
    src, chunk, summ = _world(graph, session, store)
    assert plan_rebuild(session, TENANT, src.context_id, "v1") == []  # nothing superseded yet
    v2 = _supersede(graph, session, src)

    # the stale derivative REFRESHes (a live successor exists)
    old = authorize(session, req(chunk.context_id), NOW)
    assert old.decision == Decision.REFRESH and old.reason == [ReasonCode.ANCESTOR_SUPERSEDED]

    steps = plan_rebuild(session, TENANT, src.context_id, "v1")
    assert len(steps) == 1
    assert steps[0].derivative == (chunk.context_id, "v1")
    assert steps[0].transformation == ("upper", "1")
    assert steps[0].current_inputs == [(src.context_id, "v2")]

    jobs = enqueue_rebuild(session, TENANT, src.context_id, "v1", actor="admin", now=NOW)
    session.commit()
    assert len(jobs) == 1 and jobs[0].state == "pending"
    assert enqueue_rebuild(session, TENANT, src.context_id, "v1", actor="admin", now=NOW)[0].id == jobs[0].id  # idempotent
    session.commit()

    # v2 content is in the integrator store
    store.blobs[v2.content_digest] = b"hello v2"
    runner = RebuildRunner(factory, {"upper": store.upper, "upper2": store.upper})
    r = runner.run_once(NOW)
    assert (r.leased, r.done, r.failed) == (1, 1, 0)
    session.expire_all()
    job = session.get(RebuildJobRow, jobs[0].id)
    assert job.state == "done" and job.result_context_id and job.result_version

    new_chunk = job.result_context_id
    ver = job.result_version
    assert authorize(session, req((new_chunk, ver)), NOW).decision == Decision.ALLOW
    # the rebuilt derivative hangs off the NEW parent only; the old one keeps its old lineage and verdict
    new_parents = {
        (e.parent_id, e.parent_version)
        for e in session.scalars(select(DerivationEdge).where(DerivationEdge.child_id == new_chunk))
    }
    assert new_parents == {(src.context_id, "v2")}
    old_parents = {
        (e.parent_id, e.parent_version)
        for e in session.scalars(select(DerivationEdge).where(DerivationEdge.child_id == chunk.context_id))
    }
    assert old_parents == {(src.context_id, "v1")}
    assert authorize(session, req((chunk.context_id, "v1")), NOW).decision == Decision.REFRESH
    assert store.blobs[session.get(ContextObject, (new_chunk, ver)).content_digest] == b"HELLO V2"

    # cascade: the summary (child of the old chunk) was planned against the rebuilt chunk
    nxt = session.scalars(select(RebuildJobRow).where(RebuildJobRow.derivative_context_id == summ.context_id)).one()
    assert nxt.state == "pending" and nxt.inputs == [[new_chunk, ver]]
    assert runner.run_once(NOW).done == 1
    session.expire_all()
    nxt = session.get(RebuildJobRow, nxt.id)
    assert authorize(session, req((nxt.result_context_id, nxt.result_version)), NOW).decision == Decision.ALLOW
    assert authorize(session, req((summ.context_id, "v1")), NOW).decision == Decision.REFRESH
    assert runner.run_once(NOW).leased == 0  # cascade ends: nothing is left to plan
    actions = {a.action for a in session.scalars(select(AuditLog))}
    assert {"rebuild.enqueue", "rebuild.complete"} <= actions


def test_no_handler_fails_with_clear_error(graph, session, factory):
    store = Store()
    src, _, _ = _world(graph, session, store)
    _supersede(graph, session, src)
    enqueue_rebuild(session, TENANT, src.context_id, "v1", actor="admin", now=NOW)
    session.commit()
    r = RebuildRunner(factory, {}).run_once(NOW)
    assert (r.leased, r.failed, r.done) == (1, 1, 0)
    session.expire_all()
    job = session.scalars(select(RebuildJobRow)).one()
    assert job.state == "failed" and "no rebuild handler registered for transformation 'upper'" in job.last_error
    # re-enqueue after fixing the wiring retries the same step
    again = enqueue_rebuild(session, TENANT, src.context_id, "v1", actor="admin", now=NOW)
    session.commit()
    assert again[0].id == job.id and again[0].state == "pending"
    store.blobs[session.get(ContextObject, (src.context_id, "v2")).content_digest] = b"v2"
    assert RebuildRunner(factory, {"upper": store.upper}).run_once(NOW).done == 1


def test_non_idempotent_error_is_not_retried_idempotent_is(graph, session, factory):
    store = Store()
    src, _, _ = _world(graph, session, store)
    v2 = _supersede(graph, session, src)
    store.blobs[v2.content_digest] = b"v2"
    enqueue_rebuild(session, TENANT, src.context_id, "v1", actor="admin", now=NOW)
    session.commit()
    flaky = {"n": 0}

    def boom(_inputs):
        flaky["n"] += 1
        if flaky["n"] == 1:
            raise ConnectionError("store down")
        return store.upper(_inputs)

    runner = RebuildRunner(factory, {"upper": boom, "upper2": store.upper})
    r = runner.run_once(NOW)
    assert (r.retried, r.failed) == (1, 0)  # idempotent: backoff then retry
    assert runner.run_once(NOW).leased == 0  # not due yet
    assert runner.run_once(NOW + timedelta(seconds=10)).done == 1

    # a non-idempotent transformation is never retried after an error
    session.expire_all()
    session.execute(TransformationRow.__table__.update().where(TransformationRow.transformation_id == "upper2").values(idempotent=False))
    session.commit()
    runner2 = RebuildRunner(factory, {"upper2": lambda i: (_ for _ in ()).throw(RuntimeError("half done"))})
    r2 = runner2.run_once(NOW + timedelta(seconds=20))
    assert (r2.failed, r2.retried) == (1, 0)
    session.expire_all()
    bad = session.scalars(select(RebuildJobRow).where(RebuildJobRow.state == "failed")).one()
    assert "RuntimeError: half done" in bad.last_error


def test_bad_handler_output_fails_and_registers_nothing(graph, session, factory):
    store = Store()
    src, _, _ = _world(graph, session, store)
    v2 = _supersede(graph, session, src)
    store.blobs[v2.content_digest] = b"v2"
    enqueue_rebuild(session, TENANT, src.context_id, "v1", actor="admin", now=NOW)
    session.commit()
    runner = RebuildRunner(factory, {"upper": lambda i: RebuildOutput("not-a-digest"), "upper2": store.upper}, max_attempts=1)
    assert runner.run_once(NOW).failed == 1
    session.expire_all()
    job = session.scalars(select(RebuildJobRow)).one()
    assert job.state == "failed" and "sha256" in job.last_error and job.result_context_id is None


def test_rebuild_cannot_cross_tenants(graph, session):
    store = Store()
    src, _, _ = _world(graph, session, store)
    with pytest.raises(RebuildError):
        plan_rebuild(session, OTHER, src.context_id, "v1")
    with pytest.raises(RebuildError):
        enqueue_rebuild(session, OTHER, src.context_id, "v1", actor="x")
