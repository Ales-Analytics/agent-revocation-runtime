"""Single-owner startup migrations: a Postgres advisory lock around ``run_migrations``.

N replicas starting against a fresh database would otherwise race Alembic. The first to take the lock
migrates; the others block, then run ``run_migrations`` as a no-op at head. SQLite: no lock (single file,
no multi-replica story); it simply delegates. Core migrations are untouched.
"""

from __future__ import annotations

import threading

from ales_core.migrations import run_migrations
from sqlalchemy import text
from sqlalchemy.engine import Engine

#: fixed application-wide advisory lock key ("ALES" as an int)
MIGRATION_LOCK_KEY = 0x414C4553


#: SQLite (and any non-Postgres dialect): serialise threads of this process; Alembic's env.py is not
#: thread-safe and two concurrent runs on a fresh file collide on ``alembic_version``.
_LOCAL = threading.Lock()


def run_migrations_locked(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        with _LOCAL:
            run_migrations(engine)
        return
    # A dedicated connection holds the session-level lock for the whole migration; released in finally
    # (and automatically by Postgres if the process dies).
    with engine.connect() as conn:
        conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": MIGRATION_LOCK_KEY})
        conn.commit()
        try:
            run_migrations(engine)
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": MIGRATION_LOCK_KEY})
            conn.commit()
