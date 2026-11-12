from __future__ import annotations

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from ales_core import Base, create_all
from ales_core.migrations import current_revision, downgrade_migrations, head_revision, run_migrations
from sqlalchemy import create_engine, inspect


def _engine(tmp_path, name="m.db"):
    return create_engine(f"sqlite:///{tmp_path / name}")


def test_migrations_create_schema_matching_models(tmp_path):
    eng = _engine(tmp_path)
    run_migrations(eng)
    assert current_revision(eng) == head_revision()
    with eng.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)
    assert diff == []
    tables = set(inspect(eng).get_table_names())
    assert {"tombstones", "issuer_keys", "audit_log", "invalidation_outbox", "alembic_version"} <= tables


def test_migration_is_idempotent_and_matches_create_all(tmp_path):
    a, b = _engine(tmp_path, "a.db"), _engine(tmp_path, "b.db")
    run_migrations(a)
    run_migrations(a)
    create_all(b)
    ia, ib = inspect(a), inspect(b)
    for t in set(ib.get_table_names()):
        assert {c["name"] for c in ia.get_columns(t)} == {c["name"] for c in ib.get_columns(t)}, t
        assert {i["name"] for i in ia.get_indexes(t)} == {i["name"] for i in ib.get_indexes(t)}, t


def test_downgrade_to_base(tmp_path):
    eng = _engine(tmp_path)
    run_migrations(eng)
    downgrade_migrations(eng)
    assert set(inspect(eng).get_table_names()) <= {"alembic_version"}
    run_migrations(eng)  # and back up again
    assert current_revision(eng) == head_revision()
