"""Helpers shared by the stress tests (app factory, chain builder, thread runner)."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from ales_sdk import new_derivative, new_source
from ales_server import create_app
from fastapi.testclient import TestClient

ALL = ["ingest", "revoke", "read", "admin"]
TOKENS = {
    "tok-t1": {"tenant_id": "t1", "roles": ALL, "subject": "svc-t1"},
    "tok-t2": {"tenant_id": "t2", "roles": ALL, "subject": "svc-t2"},
}
PRINCIPAL = {"type": "user", "id": "alice"}


def auth(tenant: str = "t1") -> dict[str, str]:
    return {"Authorization": f"Bearer tok-{tenant}"}


def make_app(db_url: str):
    return create_app(db_url, tokens=TOKENS, outbox_interval=0)


def tclient(app, tenant: str = "t1") -> TestClient:
    """A TestClient (no lifespan) for one thread; many may share one app."""
    return TestClient(app, headers=auth(tenant))


def post_ok(tc: TestClient, path: str, body: dict) -> dict[str, Any]:
    r = tc.post(path, json=body)
    assert r.status_code == 200, (r.status_code, r.text)
    return r.json()


def register_chain(tc: TestClient, tenant: str = "t1") -> list[dict]:
    """source -> chunk -> summary -> memory; returns the four envelopes."""
    src = new_source(tenant, "doc", b"secret", "kb", classification="confidential")
    chunk = new_derivative("chunk", [src], tenant, "chunk", b"c")
    summ = new_derivative("summary", [chunk], tenant, "summary", b"s")
    mem = new_derivative("memory", [summ], tenant, "memory", b"m")
    post_ok(tc, "/v1/sources", src)
    for env in (chunk, summ, mem):
        post_ok(tc, "/v1/derivations", env)
    return [src, chunk, summ, mem]


def authorize(tc: TestClient, tenant: str, context_id: str, purpose: str = "rag") -> str:
    r = tc.post(
        "/v1/authorize",
        json={"tenant_id": tenant, "principal": PRINCIPAL, "purpose": purpose, "objects": [{"context_id": context_id}]},
    )
    assert r.status_code == 200, (r.status_code, r.text)
    return r.json()["decision"]


def revocation_body(tenant: str, source_id: str, event_id: str | None = None, reason: str = "deleted") -> dict:
    return {
        "event_id": event_id or str(uuid.uuid4()),
        "tenant_id": tenant,
        "source_id": source_id,
        "reason": reason,
        "effective_at": datetime.now(UTC).isoformat(),
    }


def run_threads(fns: list[Callable[[], Any]], timeout: float = 120.0) -> tuple[list[Any], list[BaseException]]:
    """Run callables in threads released together by a barrier; return (results, exceptions)."""
    barrier = threading.Barrier(len(fns))
    results: list[Any] = [None] * len(fns)
    errors: list[BaseException] = []

    def wrap(i: int, fn: Callable[[], Any]) -> None:
        try:
            barrier.wait(30)
            results[i] = fn()
        except BaseException as exc:  # noqa: BLE001 - reported to the test
            errors.append(exc)

    threads = [threading.Thread(target=wrap, args=(i, f), daemon=True) for i, f in enumerate(fns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout)
    assert not any(t.is_alive() for t in threads), "thread did not finish (deadlock?)"
    return results, errors
