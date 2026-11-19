"""In-flight revocation race: what a reader that is already mid-transaction can still be told.

``authorize`` is linearised at its tombstone read. A revocation that commits *after* that read cannot
be seen by that call, so an ALLOW computed just before ``accept()`` returned may be *delivered* after it.
This is the unavoidable in-flight window. The invariants we hold (and measure) are:

 1. No ALLOW is computed from a read that STARTED after ``accept()`` returned (zero post-acceptance
    escapes), on SQLite and Postgres.
 2. A stale in-flight ALLOW is stamped with the PRE-revocation epoch (epoch is read before the lineage),
    so epoch-keyed caches treat it as outdated as soon as they see the new epoch; it never carries the
    new epoch.
 3. The delivered-late window is bounded by the duration of that one in-flight call:
    ``stale_window = response_delivered - accept_returned  <=  call_duration``.

Overall exposure for a client = in-flight transaction duration (measured here) + SDK decision-cache TTL
(``max_ttl``, default 30 s) if the ALLOW was cached; see docs/residual-risks.md R6-R9.

Run with ``-s`` to see the measured bound (lines tagged ``[inflight-bound]``).
"""

from __future__ import annotations

import statistics
import threading
import time
import uuid
from datetime import UTC, datetime

import ales_core.resolver as resolver_mod
import pytest
from ales_core import (
    AuthorizeRequest,
    ContextEnvelope,
    GraphStore,
    ObjectRef,
    Principal,
    RevocationEngine,
    RevocationEvent,
    authorize,
)
from ales_sdk import new_derivative, new_source
from sqlalchemy.orm import Session
from stress_helpers import run_threads

RUNS = 50
READERS = 4
P = Principal(type="user", id="alice")


def _chain(engine, tenant: str):
    src = new_source(tenant, "doc", b"secret", "kb", classification="confidential")
    chunk = new_derivative("chunk", [src], tenant, "chunk", b"c")
    mem = new_derivative("memory", [chunk], tenant, "memory", b"m")
    with Session(engine) as s:
        g = GraphStore(s)
        g.register_source(ContextEnvelope.model_validate(src))
        g.register_derivation(ContextEnvelope.model_validate(chunk))
        g.register_derivation(ContextEnvelope.model_validate(mem))
        s.commit()
    return src, mem


def _req(tenant: str, cid: str) -> AuthorizeRequest:
    return AuthorizeRequest(tenant_id=tenant, principal=P, purpose="rag", objects=[ObjectRef(context_id=cid)])


def _revoke(engine, tenant: str, source_id: str) -> int:
    ev = RevocationEvent(
        event_id=str(uuid.uuid4()),
        tenant_id=tenant,
        source_id=source_id,
        reason="deleted",
        effective_at=datetime.now(UTC),
    )
    with Session(engine) as s:
        return RevocationEngine().accept(s, ev)


@pytest.mark.parametrize("hold", [0.05, 0.25])
def test_in_flight_reader_serves_stale_allow_only_within_its_own_call(engine, monkeypatch, hold):
    """Deterministic: a reader is frozen between its lineage read and its verdict while the revocation
    commits. The late ALLOW is stamped with the old epoch and is delivered within ``hold`` (+slack)."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    src, mem = _chain(engine, tenant)
    real_load = resolver_mod.load_tombstones
    loaded, proceed = threading.Event(), threading.Event()
    frozen_once = threading.Event()

    def hooked(session, tenant_id, ids):
        out = real_load(session, tenant_id, ids)
        if not frozen_once.is_set():
            frozen_once.set()
            loaded.set()  # reader has read the (empty) tombstone set ...
            assert proceed.wait(30)  # ... and is now mid-transaction
            time.sleep(hold)  # ... for a further `hold` seconds
        return out

    monkeypatch.setattr(resolver_mod, "load_tombstones", hooked)
    box: dict = {}

    def reader():
        with Session(engine) as s:
            t0 = time.perf_counter()
            box["resp"] = authorize(s, _req(tenant, mem["context_id"]), datetime.now(UTC))
            box["t_end"] = time.perf_counter()
            box["dur"] = box["t_end"] - t0

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    assert loaded.wait(30)
    epoch = _revoke(engine, tenant, src["context_id"])  # commits while the reader is in flight
    t_acc = time.perf_counter()
    proceed.set()
    th.join(60)
    assert not th.is_alive() and epoch == 1

    stale = box["resp"]
    assert stale.decision.value == "ALLOW"  # in-flight: computed before the revocation committed
    assert stale.revocation_epoch == 0 < epoch  # ... and stamped with the epoch it was computed at
    window = box["t_end"] - t_acc
    assert 0 < window <= box["dur"] and window <= hold + 2.0
    print(
        f"[inflight-bound] deterministic hold={hold:.2f}s stale_window={window * 1000:.1f}ms "
        f"call={box['dur'] * 1000:.1f}ms"
    )

    # any read that starts after acceptance is denied, with the new epoch
    monkeypatch.setattr(resolver_mod, "load_tombstones", real_load)
    with Session(engine) as s:
        fresh = authorize(s, _req(tenant, mem["context_id"]), datetime.now(UTC))
    assert fresh.decision.value == "DENY" and fresh.revocation_epoch == epoch


def test_tight_loop_readers_50_runs_measure_stale_window(engine):
    """50 revocations against N tight-loop readers: zero post-acceptance escapes; measure the max
    delivered-late ALLOW window (bounded by that call's own duration)."""
    windows: list[float] = []
    durations: list[float] = []
    late_allows = 0
    for _ in range(RUNS):
        tenant = f"t-{uuid.uuid4().hex[:8]}"
        src, mem = _chain(engine, tenant)
        logs: list[list[tuple[float, float, str, int]]] = [[] for _ in range(READERS)]
        warm = [threading.Event() for _ in range(READERS)]
        stop = threading.Event()
        acc: list[float] = []
        epoch_box: list[int] = []

        def reader(i: int, tenant=tenant, mem=mem, logs=logs, warm=warm, stop=stop, acc=acc):
            with Session(engine) as s:
                n = 0
                while True:
                    t0 = time.perf_counter()
                    r = authorize(s, _req(tenant, mem["context_id"]), datetime.now(UTC))
                    t1 = time.perf_counter()
                    s.rollback()  # end the read transaction: every call starts a fresh one
                    logs[i].append((t0, t1, r.decision.value, r.revocation_epoch))
                    n += r.decision.value == "ALLOW"
                    if n >= 3:
                        warm[i].set()
                    if stop.is_set() and acc and t0 > acc[0] + 0.02:
                        return

        def revoker(warm=warm, stop=stop, acc=acc, tenant=tenant, src=src, epoch_box=epoch_box):
            for w in warm:
                assert w.wait(30)
            epoch_box.append(_revoke(engine, tenant, src["context_id"]))
            acc.append(time.perf_counter())
            time.sleep(0.1)
            stop.set()

        _, errors = run_threads([revoker] + [lambda i=i: reader(i) for i in range(READERS)])
        assert not errors, errors
        t_acc, new_epoch = acc[0], epoch_box[0]
        for log in logs:
            for t0, t1, d, ep in log:
                durations.append(t1 - t0)
                if t0 > t_acc:
                    assert d != "ALLOW", "ALLOW from a read that started after accept() returned"
                    assert ep >= new_epoch
                elif d == "ALLOW" and t1 > t_acc:  # delivered after acceptance, computed before it
                    late_allows += 1
                    windows.append(t1 - t_acc)
                    assert ep < new_epoch, "stale ALLOW stamped with the post-revocation epoch"
                    assert t1 - t_acc <= t1 - t0
        assert any(d != "ALLOW" for log in logs for _a, _b, d, _e in log)

    worst = max(windows, default=0.0)
    print(
        f"[inflight-bound] runs={RUNS} readers={READERS} late_allows={late_allows} "
        f"stale_window max={worst * 1000:.1f}ms p50={statistics.median(windows or [0.0]) * 1000:.1f}ms "
        f"| authorize call duration p50={statistics.median(durations) * 1000:.1f}ms "
        f"max={max(durations) * 1000:.1f}ms | post-acceptance escapes=0"
    )
    # the measured window can never exceed the slowest call: exposure = in-flight call + SDK cache TTL
    assert worst <= max(durations)
