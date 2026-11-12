"""Programmatic Alembic helpers. Scripts live in ``core/alembic`` (next to the package)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine

SCRIPT_LOCATION = Path(__file__).resolve().parents[1] / "alembic"


def _config(connection: Connection) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(SCRIPT_LOCATION))
    cfg.attributes["connection"] = connection
    return cfg


def head_revision() -> str | None:
    cfg = Config()
    cfg.set_main_option("script_location", str(SCRIPT_LOCATION))
    return ScriptDirectory.from_config(cfg).get_current_head()


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def run_migrations(engine: Engine, revision: str = "head") -> None:
    """Upgrade the database to ``revision`` (default head). Idempotent."""
    with engine.begin() as conn:
        command.upgrade(_config(conn), revision)


def downgrade_migrations(engine: Engine, revision: str = "base") -> None:
    with engine.begin() as conn:
        command.downgrade(_config(conn), revision)
