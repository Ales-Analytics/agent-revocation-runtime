"""Reachability checks and factories for live backing stores (Qdrant, pgvector Postgres, Redis).

Used by the container-backed tests and the conformance suite so both skip, with a clear reason, when a
store is not running. Endpoints default to the local dev containers and can be overridden::

    ALES_TEST_QDRANT_URL   http://localhost:56333
    ALES_TEST_PG_URL       postgresql+psycopg2://postgres:ci@localhost:55433/postgres
    ALES_TEST_REDIS_URL    redis://localhost:56379/0

The defaults are throwaway credentials for the disposable CI/dev containers, not real secrets.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from functools import cache
from typing import Any

QDRANT_URL = os.environ.get("ALES_TEST_QDRANT_URL", "http://localhost:56333")
PG_URL = os.environ.get("ALES_TEST_PG_URL", "postgresql+psycopg2://postgres:ci@localhost:55433/postgres")
REDIS_URL = os.environ.get("ALES_TEST_REDIS_URL", "redis://localhost:56379/0")


def qdrant_client() -> Any:
    from qdrant_client import QdrantClient

    return QdrantClient(url=QDRANT_URL, timeout=3)


def pg_engine() -> Any:
    from sqlalchemy import create_engine

    return create_engine(PG_URL, pool_pre_ping=True, connect_args={"connect_timeout": 3})


def redis_client() -> Any:
    import redis

    return redis.Redis.from_url(REDIS_URL, socket_connect_timeout=2, socket_timeout=5, decode_responses=True)


def _probe_qdrant() -> None:
    qdrant_client().get_collections()


def _probe_pg() -> None:
    from sqlalchemy import text

    eng = pg_engine()
    try:
        with eng.connect() as connection:
            connection.execute(text("SELECT 1"))
            ok = connection.execute(
                text("SELECT 1 FROM pg_available_extensions WHERE name = 'vector'")
            ).first()
        if ok is None:
            raise RuntimeError("pgvector extension not available on the server")
    finally:
        eng.dispose()


def _probe_redis() -> None:
    if not redis_client().ping():
        raise RuntimeError("PING failed")


_PROBES: dict[str, tuple[str, Callable[[], None]]] = {
    "qdrant": (QDRANT_URL, _probe_qdrant),
    "pgvector": (PG_URL.split("@")[-1], _probe_pg),
    "redis": (REDIS_URL, _probe_redis),
}


@cache
def unavailable_reason(store: str) -> str | None:
    """``None`` when ``store`` ("qdrant" | "pgvector" | "redis") is reachable, else a skip reason."""
    where, probe = _PROBES[store]
    try:
        probe()
    except Exception as exc:  # noqa: BLE001 - any failure (import, connect, auth) means "not usable"
        return f"live {store} not reachable at {where} ({type(exc).__name__}: {exc})"[:300]
    return None


def is_available(store: str) -> bool:
    return unavailable_reason(store) is None
