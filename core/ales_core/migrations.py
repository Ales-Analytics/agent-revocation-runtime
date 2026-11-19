"""Programmatic Alembic helpers. Scripts live in ``core/alembic`` (next to the package)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine

SCRIPT_LOCATION = Path(__file__).resolve().parent / "alembic"


def _config(connection: Connection) -> Config:
    configuration = Config()
    configuration.set_main_option("script_location", str(SCRIPT_LOCATION))
    configuration.attributes["connection"] = connection
    return configuration


def head_revision() -> str | None:
    configuration = Config()
    configuration.set_main_option("script_location", str(SCRIPT_LOCATION))
    return ScriptDirectory.from_config(configuration).get_current_head()


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def run_migrations(engine: Engine, revision: str = "head") -> None:
    """Upgrade the database to ``revision`` (default head). Idempotent."""
    with engine.begin() as connection:
        command.upgrade(_config(connection), revision)


def downgrade_migrations(engine: Engine, revision: str = "base") -> None:
    with engine.begin() as connection:
        command.downgrade(_config(connection), revision)
