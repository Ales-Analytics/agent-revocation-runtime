"""Alembic environment. Driven programmatically via ales_core.migrations.run_migrations(engine);
for CLI use set ``sqlalchemy.url`` (e.g. ``-x`` is not needed: export ALES_DATABASE_URL)."""

from __future__ import annotations

import os

from alembic import context
from ales_core.db import Base
from sqlalchemy import create_engine

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    url = config.get_main_option("sqlalchemy.url") or os.environ.get("ALES_DATABASE_URL")
    if not url:
        raise RuntimeError("no database URL: pass a connection or set ALES_DATABASE_URL")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is None:
        engine = create_engine(_url())
        with engine.connect() as conn:
            context.configure(connection=conn, target_metadata=target_metadata, compare_type=True)
            with context.begin_transaction():
                context.run_migrations()
        return
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
