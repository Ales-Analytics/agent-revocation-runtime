"""Two OutboxDispatchers racing over the same database: exactly-once leasing, no loss, dead letters.

Stress suite (``pytest -q stress``). Row seeding goes straight through the ORM; the dispatcher only
cares about the ``invalidation_outbox`` table.
"""

from __future__ import annotations

import threading
from collections import Counter
from datetime import UTC, datetime

from ales_core import InvalidationOutbox, OutboxDispatcher, Tenant
from sqlalchemy import select
from sqlalchemy.orm import Session

ROWS = 200


def _seed(session_factory, n: int = ROWS) -> list[int]:
    with session_factory() as s:
        s.add(Tenant(tenant_id="t1", revocation_epoch=0))
        s.flush()
        now = datetime.now(UTC)
        rows = [
            InvalidationOutbox(
                tenant_id="t1", context_id=f"c{i}", version="1", reason="deleted", store_kind="chunk",
                state="pending", available_at=now,
            )
            for i in range(n)
        ]
        s.add_all(rows)
        s.commit()
        return sorted(r.id for r in rows)


def _drain(dispatcher: OutboxDispatcher, batch: int = 10) -> None:
    while True:
        res = dispatcher.run_once(batch_size=batch)
        if res.leased == 0 and res.dead == 0:
            return


def test_two_dispatchers_process_each_row_exactly_once(session_factory):
    ids = _seed(session_factory)
    seen: list[int] = []
    lock = threading.Lock()

    def handler(row):
        with lock:
            seen.append(row.id)

    d1 = OutboxDispatcher(session_factory, {"*": handler})
    d2 = OutboxDispatcher(session_factory, {"*": handler})
    barrier = threading.Barrier(2)
    errs: list[BaseException] = []

    def run(d):
        try:
            barrier.wait(10)
            _drain(d)
        except BaseException as exc:  # noqa: BLE001
            errs.append(exc)

    ts = [threading.Thread(target=run, args=(d,)) for d in (d1, d2)]
    [t.start() for t in ts]
    [t.join(120) for t in ts]
    assert not errs, errs
    dupes = {k: v for k, v in Counter(seen).items() if v > 1}
    assert not dupes, f"double-processed rows: {dupes}"
    assert sorted(seen) == ids, "rows lost"
    with Session(session_factory.kw["bind"]) as s:
        rows = list(s.scalars(select(InvalidationOutbox)))
    assert {r.state for r in rows} == {"done"}
    assert {r.attempts for r in rows} == {1}


def test_persistently_failing_handler_dead_letters(session_factory):
    ids = _seed(session_factory, 20)

    def boom(row):
        raise RuntimeError("store down")

    d = OutboxDispatcher(session_factory, {"*": boom}, max_attempts=3)
    from datetime import timedelta

    # run two dispatchers concurrently over a simulated clock that outruns every backoff
    t0 = datetime.now(UTC)
    errs: list[BaseException] = []

    def run(offset: int):
        try:
            for step in range(1, 6):
                d.run_once(now=t0 + timedelta(seconds=step * 1000 + offset))
        except BaseException as exc:  # noqa: BLE001
            errs.append(exc)

    ts = [threading.Thread(target=run, args=(o,)) for o in (0, 1)]
    [t.start() for t in ts]
    [t.join(120) for t in ts]
    assert not errs, errs
    with session_factory() as s:
        rows = list(s.scalars(select(InvalidationOutbox)))
    assert sorted(r.id for r in rows) == ids
    assert {r.state for r in rows} == {"dead"}
    assert all(r.attempts == 3 and r.last_error for r in rows)
