"""Two real OS processes (two uvicorn servers, each with an outbox worker) over ONE database.

Stress suite (``pytest -q stress``). Server A serves client A (which keeps a decision cache with a short
TTL); server B receives the revocation. They share nothing but the database, so this proves the
revocation crosses a process boundary and that cached ALLOWs are bounded by the cache TTL (the SDK
default is 30 s; the tests shorten ``client.cache.max_ttl`` to keep runtime small).
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from ales_core import InvalidationOutbox
from ales_sdk import InvariantClient, new_derivative, new_source
from conftest import ROOT
from sqlalchemy import select
from sqlalchemy.orm import Session
from stress_helpers import TOKENS

TTL = 2.0
PRINCIPAL = {"type": "user", "id": "alice"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, db_url: str, log: Path):
        self.port = _free_port()
        env = dict(os.environ)
        env.update(
            DATABASE_URL=db_url,
            ALES_TOKENS=json.dumps(TOKENS),
            ALES_OUTBOX_INTERVAL="0.2",
            PYTHONPATH=os.pathsep.join([str(ROOT / "core"), str(ROOT / "server"), env.get("PYTHONPATH", "")]),
        )
        self._log = open(log, "wb")  # noqa: SIM115 - lives as long as the process
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "ales_server.main:app", "--host", "127.0.0.1",
             "--port", str(self.port), "--log-level", "warning"],
            env=env, stdout=self._log, stderr=subprocess.STDOUT,
        )
        self.url = f"http://127.0.0.1:{self.port}"
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"server exited early: {log.read_text(errors='replace')[-2000:]}")
            try:
                if httpx.get(self.url + "/v1/readyz", timeout=1).status_code == 200:
                    return
            except httpx.TransportError:
                time.sleep(0.1)
        self.stop()
        raise RuntimeError("server did not become ready")

    def client(self, ttl: float | None = None) -> InvariantClient:
        client = InvariantClient(self.url, "t1", "tok-t1", max_retries=0)
        if ttl is not None:
            # NOT ``cache=DecisionCache(max_ttl=ttl)``: client.py does ``cache or DecisionCache()`` and an
            # empty DecisionCache is falsy (``__len__`` == 0), so a caller-supplied empty cache is silently
            # replaced by the 30 s default (SDK bug, reported separately; sdk-python is out of scope here).
            client.cache.max_ttl = ttl
        return client

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self._log.close()


@pytest.fixture
def servers(db_url, tmp_path):
    a = Server(db_url, tmp_path / "a.log")  # A first: it runs the (idempotent) migrations
    b = Server(db_url, tmp_path / "b.log")
    try:
        yield a, b
    finally:
        b.stop()
        a.stop()


def _chain(c: InvariantClient, name: str) -> list[dict]:
    src = new_source("t1", name, b"secret", "kb", classification="confidential")
    chunk = new_derivative("chunk", [src], "t1", "chunk", b"c")
    mem = new_derivative("memory", [chunk], "t1", "memory", b"m")
    c.register_source(src)
    c.register_derivation(chunk)
    c.register_derivation(mem)
    return [src, chunk, mem]


def test_cached_allow_is_bounded_by_ttl_across_processes(servers):
    a, b = servers
    ca, cb = a.client(ttl=TTL), b.client()
    chain = _chain(cb, "doc")  # registered through B, visible through A
    target = chain[2]["context_id"]

    assert ca.authorize(PRINCIPAL, "rag", [target]).allowed
    assert ca.authorize(PRINCIPAL, "rag", [target]).from_cache

    cb.submit_revocation({"source_id": chain[0]["context_id"], "reason": "deleted"})
    t_accept = time.monotonic()

    # A fresh (uncached) client against server A denies IMMEDIATELY: no cross-process lag in the server.
    fresh = a.client()
    assert not fresh.authorize(PRINCIPAL, "rag", [target]).allowed

    # The caching client may serve the stale ALLOW only until its TTL, then must go to the server.
    stale_served = 0
    while True:
        r = ca.authorize(PRINCIPAL, "rag", [target])
        if not r.allowed:
            break
        stale_served += 1
        assert time.monotonic() - t_accept < TTL + 2.0, "cached ALLOW outlived the cache TTL"
        time.sleep(0.05)
    window = time.monotonic() - t_accept
    assert not r.from_cache  # the DENY came from a server contact
    assert window <= TTL + 1.0, f"stale window {window:.2f}s exceeds TTL {TTL}s"
    print(f"\nstale ALLOW window across processes: {window:.2f}s ({stale_served} cached reads, TTL {TTL}s)")


def test_next_server_contact_invalidates_cached_allow(servers):
    a, b = servers
    ca, cb = a.client(ttl=30.0), b.client()  # the real default TTL: only the epoch can save us
    x = _chain(cb, "x")
    y = _chain(cb, "y")
    assert ca.authorize(PRINCIPAL, "rag", [x[2]["context_id"]]).allowed
    assert ca.authorize(PRINCIPAL, "rag", [x[2]["context_id"]]).from_cache

    cb.submit_revocation({"source_id": x[0]["context_id"], "reason": "deleted"})

    # Any server contact by A (here: a different, uncached object) carries the new epoch ...
    assert ca.authorize(PRINCIPAL, "rag", [y[2]["context_id"]]).allowed
    # ... which wipes A's stale entry: the very next read of x is a (denied) server decision.
    r = ca.authorize(PRINCIPAL, "rag", [x[2]["context_id"]])
    assert not r.allowed and not r.from_cache


def test_outbox_workers_in_two_processes_drain_exactly_once(servers, engine):
    _a, b = servers
    cb = b.client()
    chain = _chain(cb, "doc")
    cb.submit_revocation({"source_id": chain[0]["context_id"], "reason": "deleted"})

    deadline = time.time() + 20
    rows: list[InvalidationOutbox] = []
    while time.time() < deadline:
        with Session(engine) as s:
            rows = list(s.scalars(select(InvalidationOutbox)))
        if len(rows) == 3 and all(r.state == "done" for r in rows):
            break
        time.sleep(0.2)
    assert len(rows) == 3, rows
    assert {r.state for r in rows} == {"done"}, [(r.state, r.last_error) for r in rows]
    # Two workers in two processes polled the same rows: a lease is single-flight, so each row ran once.
    assert {r.attempts for r in rows} == {1}

