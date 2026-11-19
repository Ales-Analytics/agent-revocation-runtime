"""Real-infrastructure plumbing for the ``postgres`` profile.

* a throw-away Postgres database per environment (same pattern as ``stress/conftest.py``);
* the control plane as a real ``uvicorn`` subprocess on a free port, configured only through the same
  environment variables a deployment uses (``DATABASE_URL``, ``ALES_TOKENS``, ...);
* a real Redis (``redis-py``) behind the redis-like interface ``GuardedCache`` and the purge handlers expect.

Nothing here is imported by the in-process profile except for the profile plumbing itself.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from ales_adapters.redis_cache import DictRedis
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import sessionmaker

from ._paths import REPO_ROOT

PROFILES = ("inprocess", "postgres")


@dataclass(frozen=True)
class ProfileInfo:
    name: str
    database: str
    transport: str


INFO = {
    "inprocess": ProfileInfo("inprocess", "sqlite-inmem", "inprocess"),
    "postgres": ProfileInfo("postgres", "postgres", "http"),
}

_active = "inprocess"


def active_profile() -> str:
    return _active


def set_profile(name: str) -> None:
    global _active
    if name not in PROFILES:
        raise ValueError(f"unknown profile {name!r}; expected one of {PROFILES}")
    _active = name


def postgres_url() -> str:
    url = os.environ.get("BENCH_POSTGRES_URL")
    if not url:
        raise RuntimeError(
            "profile 'postgres' requires BENCH_POSTGRES_URL (a superuser-capable SQLAlchemy URL)"
        )
    return url


def redis_url() -> str:
    url = os.environ.get("BENCH_REDIS_URL")
    if not url:
        raise RuntimeError("profile 'postgres' requires BENCH_REDIS_URL (e.g. redis://localhost:6379/0)")
    return url


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class BenchDictRedis(DictRedis):
    """In-process redis stand-in with the ``has`` probe the harness uses on either backend."""

    def has(self, key: str) -> bool:
        return key in self.data

    def cleanup(self) -> None:
        self.data.clear()


class StickyDictRedis(BenchDictRedis):
    """A redis whose purge never lands: the entry stays physically present after the block."""

    def delete(self, *keys: str) -> int:
        return 0


class RealRedis:
    """redis-py behind the ``get``/``set``/``delete`` interface; remembers the keys it wrote for cleanup."""

    def __init__(self, url: str | None = None) -> None:
        import redis

        self.client = redis.Redis.from_url(url or redis_url(), decode_responses=True)
        self.client.ping()
        self.touched: set[str] = set()

    def get(self, key: str) -> str | None:
        return self.client.get(key)

    def set(self, key: str, value: str, *args: Any, **kw: Any) -> bool:
        self.touched.add(key)
        return bool(self.client.set(key, value, *args, **kw))

    def delete(self, *keys: str) -> int:
        return int(self.client.delete(*keys))

    def has(self, key: str) -> bool:
        return bool(self.client.exists(key))

    def cleanup(self) -> None:
        with contextlib.suppress(Exception):
            if self.touched:
                self.client.delete(*self.touched)
        with contextlib.suppress(Exception):
            self.client.close()


class StickyRealRedis(RealRedis):
    def delete(self, *keys: str) -> int:
        return 0


class RemoteServer:
    """A migrated throw-away Postgres database plus a uvicorn subprocess serving it."""

    def __init__(
        self,
        tokens: dict[str, Any],
        *,
        require_signatures: bool = False,
        snapshot_seed: bytes | None = None,
    ) -> None:
        self.tokens = tokens
        admin_url = make_url(postgres_url())
        self.db_name = "ales_bench_" + uuid.uuid4().hex[:12]
        self._admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
        with self._admin.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{self.db_name}"'))
        self.database_url = admin_url.set(database=self.db_name).render_as_string(hide_password=False)
        self.engine: Engine = create_engine(
            self.database_url, pool_pre_ping=True, pool_size=10, max_overflow=10
        )
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.port = free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        env = {k: v for k, v in os.environ.items() if not k.startswith("ALES_") and k != "DATABASE_URL"}
        env.update(
            {
                "DATABASE_URL": self.database_url,
                "ALES_TOKENS": json.dumps(tokens),
                "ALES_OUTBOX_INTERVAL": "0",  # the harness drives the dispatcher itself, like in-process
                "ALES_REQUIRE_SIGNATURES": "1" if require_signatures else "0",
                "ALES_SNAPSHOT_KEY": base64.b64encode(snapshot_seed or os.urandom(32)).decode(),
                "PYTHONPATH": os.pathsep.join(
                    str(REPO_ROOT / d) for d in ("core", "server", "sdk-python", "adapters")
                ),
            }
        )
        self._log = tempfile.NamedTemporaryFile(  # noqa: SIM115
            "w+", prefix="ales-bench-server-", suffix=".log", delete=False
        )
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "ales_server.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--log-level",
                "warning",
            ],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=self._log,
            stderr=subprocess.STDOUT,
        )
        try:
            self._wait_ready()
        except BaseException:
            self.close()
            raise

    def _wait_ready(self, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"benchmark server exited early:\n{self.log_tail()}")
            try:
                if httpx.get(f"{self.base_url}/v1/readyz", timeout=2).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.15)
        raise RuntimeError(f"benchmark server not ready after {timeout}s:\n{self.log_tail()}")

    def log_tail(self, n: int = 4000) -> str:
        try:
            self._log.flush()
            return Path(self._log.name).read_text(errors="replace")[-n:]
        except Exception:  # noqa: BLE001
            return ""

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        with contextlib.suppress(Exception):
            self.engine.dispose()
        with contextlib.suppress(Exception), self._admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{self.db_name}" WITH (FORCE)'))
        with contextlib.suppress(Exception):
            self._admin.dispose()
        with contextlib.suppress(Exception):
            self._log.close()
            os.unlink(self._log.name)
