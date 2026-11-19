from __future__ import annotations

import threading
import uuid
from datetime import timedelta

import pytest
from ales_core import (
    BACKOFF_SECONDS,
    Decision,
    InvalidationOutbox,
    OutboxDispatcher,
    RevocationEngine,
    RevocationEvent,
    authorize,
    create_all,
    outbox_stats,
)
from core_fixtures import NOW, TENANT, req
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker


def revoke(session, chain, at=None):
    RevocationEngine().accept(
        session,
        RevocationEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=TENANT,
            source_id=chain["source"].context_id,
            reason="deleted",
            effective_at=at or NOW,
        ),
        now=NOW,
    )


@pytest.fixture
def factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)


def states(session):
    session.expire_all()
    return sorted((r.store_kind, r.state) for r in session.scalars(select(InvalidationOutbox)))


def row_state(session, kind):
    session.expire_all()
    return session.scalars(select(InvalidationOutbox).where(InvalidationOutbox.store_kind == kind)).one()


def test_happy_path_marks_done(session, chain, factory):
    revoke(session, chain)
    seen = []
    d = OutboxDispatcher(factory, {"*": lambda r: seen.append((r.store_kind, r.context_id, r.version))})
    res = d.run_once(NOW)
    assert (res.leased, res.done, res.failed, res.dead) == (4, 4, 0, 0)
    assert len(seen) == 4
    assert states(session) == [(k, "done") for k in ("chunk", "memory", "source", "summary")]
    assert all(r.dispatched and r.lease_token is None for r in session.scalars(select(InvalidationOutbox)))
    assert d.run_once(NOW).leased == 0  # nothing left


def test_routes_by_store_kind_and_ignores_unhandled(session, chain, factory):
    revoke(session, chain)
    got = []
    d = OutboxDispatcher(factory, {"chunk": lambda r: got.append(r.store_kind)})
    assert d.run_once(NOW).done == 1
    assert got == ["chunk"]
    assert row_state(session, "memory").state == "pending" and row_state(session, "memory").attempts == 0


def test_batch_size(session, chain, factory):
    revoke(session, chain)
    d = OutboxDispatcher(factory, {"*": lambda r: None})
    assert d.run_once(NOW, batch_size=3).done == 3
    assert d.run_once(NOW, batch_size=3).done == 1


def test_not_dispatched_before_available_at(session, chain, factory):
    revoke(session, chain, at=NOW + timedelta(hours=1))
    d = OutboxDispatcher(factory, {"*": lambda r: None})
    assert d.run_once(NOW).leased == 0
    assert d.run_once(NOW + timedelta(hours=1)).done == 4


def test_failure_backoff_then_dead_and_deny_throughout(session, chain, factory):
    revoke(session, chain)
    mem = chain["memory"].context_id
    calls = []

    def boom(row):
        calls.append(row.id)
        raise RuntimeError("vector store down")

    d = OutboxDispatcher(factory, {"memory": boom})
    now = NOW
    delays = [0, *BACKOFF_SECONDS]
    for i, delay in enumerate(delays):
        assert authorize(session, req(mem), now).decision == Decision.DENY
        # not yet due one second before the scheduled retry
        if i:
            assert d.run_once(now - timedelta(seconds=1)).leased == 0
        res = d.run_once(now)
        assert res.leased == 1 and res.failed == 1
        r = row_state(session, "memory")
        assert r.attempts == i + 1 and "vector store down" in r.last_error
        if i < len(BACKOFF_SECONDS):
            assert r.state == "pending"
            assert (r.available_at - now) == timedelta(seconds=BACKOFF_SECONDS[i])
            now = r.available_at
        else:
            assert r.state == "dead" and res.dead == 1
    assert len(calls) == len(BACKOFF_SECONDS) + 1
    assert authorize(session, req(mem), now + timedelta(days=1)).decision == Decision.DENY
    assert d.run_once(now + timedelta(days=1)).leased == 0  # dead is terminal
    stats = outbox_stats(session, TENANT)
    assert stats["dead"] == 1 and stats["totals"]["pending"] == 3
    assert stats["by_store_kind"]["memory"] == {"dead": 1}


def test_failure_then_success_on_retry(session, chain, factory):
    revoke(session, chain)
    attempts = {"n": 0}

    def flaky(row):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise OSError("boom")

    d2 = OutboxDispatcher(factory, {"memory": flaky})
    t = NOW
    for _ in range(3):
        d2.run_once(t)
        t = t + timedelta(seconds=10)
    r = row_state(session, "memory")
    assert r.state == "done" and r.attempts == 3 and r.last_error is None


def test_handler_error_does_not_abort_batch(session, chain, factory):
    revoke(session, chain)

    def h(row):
        if row.store_kind == "chunk":
            raise ValueError("x")

    res = OutboxDispatcher(factory, {"*": h}).run_once(NOW)
    assert (res.done, res.failed) == (3, 1)


def test_single_flight_live_lease_blocks_second_dispatcher(session, chain, factory):
    revoke(session, chain)
    processed = []
    inner = {}

    def slow(row):
        processed.append(("d1", row.id))
        # while d1 holds the lease, d2 must not touch the row
        inner[row.id] = d2.run_once(NOW + timedelta(seconds=5))

    d1 = OutboxDispatcher(factory, {"memory": slow}, lease_seconds=60)
    d2 = OutboxDispatcher(factory, {"memory": lambda r: processed.append(("d2", r.id))}, lease_seconds=60)
    res = d1.run_once(NOW)
    assert res.done == 1
    assert [p[0] for p in processed] == ["d1"]
    assert all(r.leased == 0 for r in inner.values())


def test_stale_lease_reclaimed_and_late_finisher_cannot_overwrite(session, chain, factory):
    revoke(session, chain)
    log = []
    inner = {}

    def crashy(row):
        log.append("d1")
        # d1 stalls past its lease; d2 (later clock) reclaims and completes the row
        inner["d2"] = d2.run_once(NOW + timedelta(seconds=61))
        raise RuntimeError("d1 fails after losing the lease")

    d1 = OutboxDispatcher(factory, {"memory": crashy}, lease_seconds=60)
    d2 = OutboxDispatcher(factory, {"memory": lambda r: log.append("d2")}, lease_seconds=60)
    res = d1.run_once(NOW)
    assert inner["d2"].done == 1
    assert log == ["d1", "d2"]  # redelivery: handler ran twice, so handlers must be idempotent
    assert res.lost_lease == 1 and res.done == 0 and res.failed == 0
    r = row_state(session, "memory")
    assert r.state == "done" and r.attempts == 2 and r.last_error is None


def test_exhausted_expired_lease_goes_dead(session, chain, factory):
    revoke(session, chain)
    row = row_state(session, "memory")
    row.state, row.attempts, row.lease_token = "leased", 6, "ghost"
    row.lease_expires_at = NOW - timedelta(seconds=1)
    session.commit()
    res = OutboxDispatcher(factory, {"memory": lambda r: pytest.fail("must not run")}).run_once(NOW)
    assert res.leased == 0 and res.dead == 1
    assert row_state(session, "memory").state == "dead"


def test_crash_between_tombstone_and_purge_never_reexposes(session, chain, factory):
    mem = chain["memory"].context_id
    revoke(session, chain)  # "process dies" here: no dispatcher ran, nothing purged
    assert authorize(session, req(mem), NOW).decision == Decision.DENY
    # a worker leased the row then died: lease never released
    row = row_state(session, "memory")
    row.state, row.attempts, row.lease_token = "leased", 1, "dead-worker"
    row.lease_expires_at = NOW + timedelta(seconds=60)
    session.commit()
    assert authorize(session, req(mem), NOW).decision == Decision.DENY
    assert OutboxDispatcher(factory, {"memory": lambda r: None}).run_once(NOW).leased == 0
    assert authorize(session, req(mem), NOW + timedelta(seconds=30)).decision == Decision.DENY
    res = OutboxDispatcher(factory, {"memory": lambda r: None}).run_once(NOW + timedelta(seconds=61))
    assert res.done == 1
    assert authorize(session, req(mem), NOW + timedelta(seconds=62)).decision == Decision.DENY


def test_idempotent_redelivery_safe(session, chain, factory):
    revoke(session, chain)
    purged: set = set()
    d = OutboxDispatcher(factory, {"*": lambda r: purged.add((r.context_id, r.version))})
    d.run_once(NOW)
    row = row_state(session, "chunk")
    row.state, row.dispatched = "pending", False
    session.commit()
    d.run_once(NOW)
    assert len(purged) == 4  # set semantics: second delivery changed nothing


def test_validation():
    with pytest.raises(ValueError):
        OutboxDispatcher(lambda: None, {}, lease_seconds=0)


def test_two_threads_never_double_process(tmp_path):
    """Real concurrency over a file-backed DB: each row handled by exactly one dispatcher."""
    from core_fixtures import make_env

    eng = create_engine(f"sqlite:///{tmp_path / 'o.db'}", connect_args={"timeout": 30})
    create_all(eng)
    sf = sessionmaker(bind=eng, expire_on_commit=False)
    with sf() as s:
        from ales_core import GraphStore

        g = GraphStore(s)
        src = make_env("source")
        g.register_source(src)
        for _ in range(30):
            g.register_derivation(make_env("chunk", [(src.context_id, "v1")]))
        s.commit()
        RevocationEngine().accept(
            s,
            RevocationEvent(
                event_id=str(uuid.uuid4()),
                tenant_id=TENANT,
                source_id=src.context_id,
                reason="deleted",
                effective_at=NOW,
            ),
            now=NOW,
        )
    seen: list[int] = []
    lock = threading.Lock()

    def handler(row):
        with lock:
            seen.append(row.id)

    errors: list[BaseException] = []

    def work():
        try:
            d = OutboxDispatcher(sf, {"*": handler})
            for _ in range(10):
                d.run_once(NOW, batch_size=7)
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    ts = [threading.Thread(target=work) for _ in range(2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors, errors
    assert len(seen) == len(set(seen)) == 31
    with Session(eng) as s:
        assert {r.state for r in s.scalars(select(InvalidationOutbox))} == {"done"}
    eng.dispose()
