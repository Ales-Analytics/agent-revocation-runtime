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


NEW_TABLES = {"policy_documents", "workloads", "workload_grants", "delegations", "approvals"}


def test_0002_upgrades_from_0001_and_downgrades(tmp_path):
    eng = _engine(tmp_path)
    run_migrations(eng, "0001")
    assert current_revision(eng) == "0001"
    assert not NEW_TABLES & set(inspect(eng).get_table_names())
    # existing data survives the upgrade
    with eng.begin() as conn:
        conn.exec_driver_sql("INSERT INTO tenants (tenant_id, revocation_epoch) VALUES ('t', 3)")
    run_migrations(eng, "head")
    assert current_revision(eng) == head_revision()
    assert NEW_TABLES <= set(inspect(eng).get_table_names())
    with eng.connect() as conn:
        assert conn.exec_driver_sql("SELECT revocation_epoch FROM tenants").scalar() == 3
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)
    assert diff == []
    downgrade_migrations(eng, "0001")
    assert current_revision(eng) == "0001"
    assert not NEW_TABLES & set(inspect(eng).get_table_names())
    run_migrations(eng)
    assert current_revision(eng) == head_revision()


def test_0002_schema_equals_create_all(tmp_path):
    a, b = _engine(tmp_path, "a.db"), _engine(tmp_path, "b.db")
    run_migrations(a)
    create_all(b)
    ia, ib = inspect(a), inspect(b)
    assert NEW_TABLES <= set(ib.get_table_names())
    for t in NEW_TABLES:
        assert [(c["name"], str(c["type"]), c["nullable"]) for c in ia.get_columns(t)] == [
            (c["name"], str(c["type"]), c["nullable"]) for c in ib.get_columns(t)
        ], t
        assert {u["name"] for u in ia.get_unique_constraints(t)} == {
            u["name"] for u in ib.get_unique_constraints(t)
        }, t
        assert {i["name"] for i in ia.get_indexes(t)} == {i["name"] for i in ib.get_indexes(t)}, t


def test_0003_adds_requester_columns_and_roundtrips(tmp_path):
    eng = _engine(tmp_path)
    run_migrations(eng, "0002")
    assert current_revision(eng) == "0002"
    cols = {c["name"] for c in inspect(eng).get_columns("approvals")}
    assert not {"requested_by_principal", "requested_actor"} & cols
    with eng.begin() as conn:  # a pre-0003 row survives, with NULL requesters
        conn.exec_driver_sql("INSERT INTO tenants (tenant_id, revocation_epoch) VALUES ('t', 0)")
        conn.exec_driver_sql(
            "INSERT INTO approvals (approval_id, tenant_id, fingerprint, decision_context, state, created_at)"
            " VALUES ('a1', 't', 'f', '{}', 'pending', '2026-01-01 00:00:00')"
        )
    run_migrations(eng, "0003")
    assert current_revision(eng) == "0003"
    cols = {c["name"] for c in inspect(eng).get_columns("approvals")}
    assert {"requested_by_principal", "requested_actor"} <= cols
    with eng.connect() as conn:
        row = conn.exec_driver_sql("SELECT requested_by_principal, requested_actor FROM approvals").one()
        assert tuple(row) == (None, None)
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)
    # only the (later) 0004-0006 additions may be outstanding at 0003
    later = ("context_objects", "release_receipts", "transformations", "rebuild_jobs", "session_")
    assert all(any(t in str(d) for t in later) for d in diff)
    assert {i["name"] for i in inspect(eng).get_indexes("approvals")} == {"ix_approvals_fp"}
    downgrade_migrations(eng, "0002")
    assert current_revision(eng) == "0002"
    cols = {c["name"] for c in inspect(eng).get_columns("approvals")}
    assert not {"requested_by_principal", "requested_actor"} & cols
    with eng.connect() as conn:
        assert conn.exec_driver_sql("SELECT count(*) FROM approvals").scalar() == 1
    run_migrations(eng)
    assert current_revision(eng) == head_revision() == "0006"


LIFECYCLE_TABLES = {"transformations", "rebuild_jobs", "session_exposures", "session_states"}


def test_0006_lifecycle_tables_and_derivative_tag_roundtrip(tmp_path):
    eng = _engine(tmp_path)
    run_migrations(eng, "0005")
    assert not LIFECYCLE_TABLES & set(inspect(eng).get_table_names())
    assert not {"transformation_id", "transformation_version"} & {
        c["name"] for c in inspect(eng).get_columns("context_objects")
    }
    with eng.begin() as conn:  # an existing object survives with NULL transformation
        conn.exec_driver_sql("INSERT INTO tenants (tenant_id, revocation_epoch) VALUES ('t', 0)")
        conn.exec_driver_sql(
            "INSERT INTO context_objects (context_id, object_version, tenant_id, object_id, kind, content_digest,"
            " classification, trust_state, principal_scope, purpose_scope, valid_from, source_system, policy_version,"
            " tombstoned) VALUES ('c', 'v', 't', 'o', 'source', 'sha256:x', 'internal', 'verified', 'null', 'null',"
            " '2026-01-01 00:00:00', 's', 'p0', 0)"
        )
    run_migrations(eng)
    assert current_revision(eng) == "0006"
    assert LIFECYCLE_TABLES <= set(inspect(eng).get_table_names())
    with eng.connect() as conn:
        row = conn.exec_driver_sql(
            "SELECT transformation_id, transformation_version FROM context_objects"
        ).one()
        assert tuple(row) == (None, None)
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)
    assert diff == []
    downgrade_migrations(eng, "0005")
    assert current_revision(eng) == "0005"
    assert not LIFECYCLE_TABLES & set(inspect(eng).get_table_names())
    with eng.connect() as conn:
        assert conn.exec_driver_sql("SELECT count(*) FROM context_objects").scalar() == 1
    run_migrations(eng)
    assert current_revision(eng) == head_revision()
