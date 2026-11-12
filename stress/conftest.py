"""Shared fixtures for the stress suite (path setup, database matrix, app factory).

``db_url`` is parametrised over a file-backed SQLite database (always) and a throw-away Postgres
database (only when ``TEST_POSTGRES_URL`` is set; otherwise those params are skipped). Every
test gets a brand-new, migrated database, so tests never see each other's rows.
"""

from __future__ import annotations

import os
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk-python"))
for _p in (ROOT / "core", ROOT / "server"):  # appended: installed copies win
    if str(_p) not in sys.path:
        sys.path.append(str(_p))

from ales_core.migrations import run_migrations
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

PG_URL = os.environ.get("TEST_POSTGRES_URL")

_PARAMS = [
    pytest.param("sqlite", id="sqlite"),
    pytest.param(
        "postgres",
        id="postgres",
        marks=pytest.mark.skipif(not PG_URL, reason="TEST_POSTGRES_URL not set"),
    ),
]


def make_engine(url: str):
    if make_url(url).get_backend_name() == "sqlite":
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url, pool_pre_ping=True, pool_size=20, max_overflow=20)


@pytest.fixture(params=_PARAMS)
def db_url(request, tmp_path) -> Iterator[str]:
    """URL of a fresh, fully migrated database (alembic head)."""
    if request.param == "sqlite":
        url = f"sqlite:///{(tmp_path / 'stress.db').as_posix()}"
        eng = make_engine(url)
        run_migrations(eng)
        eng.dispose()
        yield url
        return

    assert PG_URL
    admin_url = make_url(PG_URL)
    name = "ales_stress_" + uuid.uuid4().hex[:12]
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = admin_url.set(database=name).render_as_string(hide_password=False)
    eng = make_engine(url)
    run_migrations(eng)
    eng.dispose()
    try:
        yield url
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture
def engine(db_url):
    eng = make_engine(db_url)
    yield eng
    eng.dispose()


@pytest.fixture
def session_factory(engine):
    from sqlalchemy.orm import sessionmaker

    return sessionmaker(bind=engine, expire_on_commit=False)
