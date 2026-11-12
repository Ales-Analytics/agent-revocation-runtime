"""Core race test: readers hammer /v1/authorize while one thread revokes the source.

NOTE: stress suite, deliberately NOT in pyproject testpaths (slower). CI runs it explicitly:
``pytest -q stress``. File-backed SQLite serialises writers, so the SQLite param is mostly a smoke
test of the invariant; the Postgres param (TEST_POSTGRES_URL) is where real concurrency happens.

Invariants:
 1. Per reader thread: once a DENY-ish decision is observed, no later call observes ALLOW.
 2. Any authorize call that STARTS after accept() returned is not ALLOW (zero escapes).
 3. Sequential authorize after acceptance is denied for every node of the lineage.
"""

from __future__ import annotations

import threading
import time

import pytest
from stress_helpers import (
    authorize,
    make_app,
    post_ok,
    register_chain,
    revocation_body,
    run_threads,
    tclient,
)

READERS = 6


@pytest.mark.parametrize("rounds", [1, 2])
def test_no_allow_after_revocation_accepted(db_url, rounds):
    app = make_app(db_url)
    for _ in range(rounds):
        _one_round(app)


def _one_round(app):
    if True:
        main = tclient(app)
        chain = register_chain(main)
        source_id = chain[0]["context_id"]
        target = chain[3]["context_id"]  # memory: deepest descendant

        accepted_at: list[float] = []
        warm = [threading.Event() for _ in range(READERS)]
        stop = threading.Event()
        logs: list[list[tuple[float, float, str]]] = [[] for _ in range(READERS)]

        def reader(i: int):
            try:
                _reader(i)
            except BaseException:
                stop.set()
                accepted_at.append(0.0)  # unblock sibling loops; the error is reported by the harness
                raise

        def _reader(i: int):
            tc = tclient(app)
            seen = 0
            while True:
                start = time.perf_counter()
                d = authorize(tc, "t1", target)
                end = time.perf_counter()
                logs[i].append((start, end, d))
                seen += d == "ALLOW"
                if seen >= 3:
                    warm[i].set()
                # keep going until the revoker finished and we have a post-acceptance sample
                if stop.is_set() and accepted_at and start > accepted_at[0] + 0.05:
                    return

        def revoker():
            tc = tclient(app)
            for w in warm:
                if not w.wait(30):
                    stop.set()
                    accepted_at.append(0.0)
                    raise AssertionError("readers never warmed up")
            r = post_ok(tc, "/v1/revocations", revocation_body("t1", source_id))
            accepted_at.append(time.perf_counter())
            assert r["revocation_epoch"] >= 1
            time.sleep(0.2)
            stop.set()

        _, errors = run_threads([revoker] + [lambda i=i: reader(i) for i in range(READERS)])
        assert not errors, errors

        t_acc = accepted_at[0]
        # 1. monotone per thread: ALLOW* then non-ALLOW*
        for i, log in enumerate(logs):
            denied = False
            for _s, _e, d in log:
                if d != "ALLOW":
                    denied = True
                elif denied:
                    pytest.fail(f"reader {i}: ALLOW observed after a DENY")
        # 2. zero escapes after acceptance
        late = [(s, d) for log in logs for (s, _e, d) in log if s > t_acc]
        assert late, "no post-acceptance reads were sampled"
        escapes = [x for x in late if x[1] == "ALLOW"]
        assert not escapes, f"{len(escapes)} ALLOW(s) started after revocation was accepted"
        assert any(d == "ALLOW" for log in logs for (_s, _e, d) in log), "no pre-revocation ALLOW observed"
        # 3. every node of the lineage now denies
        for env in chain:
            assert authorize(main, "t1", env["context_id"]) != "ALLOW"
