"""``python -m ales_server.preflight``: PASS/WARN/FAIL matrices over env dicts (no network; sqlite tmp DB)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from ales_server import preflight
from ales_server.preflight import FAIL, PASS, WARN, run_preflight
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "adapters"))
from server_helpers import ROOT, seed_b64

TOKENS = json.dumps({"tok-1": {"tenant_id": "t1", "roles": ["read", "admin"], "subject": "svc"}})
KEY = seed_b64(Ed25519PrivateKey.generate())


def _migrated_db(tmp_path):
    from ales_core.migrations import run_migrations
    from ales_server.hardening import make_engine

    db = tmp_path / "ok.db"
    eng = make_engine(f"sqlite:///{db}")
    run_migrations(eng)
    eng.dispose()
    return f"sqlite:///{db}"


def good_prod(tmp_path, **over):
    env = {
        "ALES_ENV": "production",
        "ALES_TOKENS": TOKENS,
        "ALES_REQUIRE_SIGNATURES": "1",
        "ALES_SNAPSHOT_KEY": KEY,
        "ALES_ALLOW_SQLITE": "1",
        "ALES_PURGE_POLICY": "deny-only",
        "DATABASE_URL": _migrated_db(tmp_path),
        "ALES_AUDIT_EXPORT_FILE": str(tmp_path / "audit.ndjson"),
    }
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


def status(rep, name):
    return rep.by_name(name).status


def test_good_production_has_no_fail_and_warns_only_for_deny_only(tmp_path):
    rep = run_preflight(good_prod(tmp_path))
    assert rep.exit_code == 0, rep.render()
    assert status(rep, "production_rules") == PASS
    assert status(rep, "purge") == WARN  # deny-only is explicit but still a warning
    assert status(rep, "database") == PASS
    assert status(rep, "snapshot_key") == PASS
    assert status(rep, "authentication") == PASS
    assert status(rep, "workloads") == PASS and status(rep, "grants") == PASS
    assert status(rep, "audit_export") == PASS


def test_production_with_importable_targets_passes_purge(tmp_path):
    targets = json.dumps([{"kind": "cache", "type": "redis", "url": "redis://127.0.0.1:1/0"}])
    rep = run_preflight(good_prod(tmp_path, ALES_PURGE_POLICY="purge", ALES_PURGE_TARGETS=targets))
    assert rep.exit_code == 0, rep.render()
    assert status(rep, "purge") == PASS and "redis" in rep.by_name("purge").detail


def test_production_no_targets_policy_purge_fails_twice_over(tmp_path):
    rep = run_preflight(good_prod(tmp_path, ALES_PURGE_POLICY="purge"))
    assert rep.exit_code == 1
    assert status(rep, "purge") == FAIL
    assert any(c.status == FAIL and c.name.startswith("production_rule") and "ALES_PURGE_TARGETS" in c.detail
               for c in rep.checks)


def test_bad_target_spec_and_missing_client_lib_fail(tmp_path, monkeypatch):
    rep = run_preflight(good_prod(tmp_path, ALES_PURGE_POLICY="purge", ALES_PURGE_TARGETS="garbage"))
    assert status(rep, "purge") == FAIL
    monkeypatch.setitem(sys.modules, "redis", None)
    targets = json.dumps([{"kind": "cache", "type": "redis", "url": "redis://x"}])
    rep = run_preflight(good_prod(tmp_path, ALES_PURGE_POLICY="purge", ALES_PURGE_TARGETS=targets))
    assert status(rep, "purge") == FAIL and "redis" in rep.by_name("purge").detail


def test_production_violations_each_surface_as_fail(tmp_path):
    rep = run_preflight(good_prod(tmp_path, ALES_TOKENS=None, ALES_REQUIRE_SIGNATURES=None, ALES_SNAPSHOT_KEY=None,
                                  ALES_ALLOW_SQLITE=None, ALES_ENFORCE_WORKLOADS="off"))
    fails = [c for c in rep.checks if c.status == FAIL]
    text = " | ".join(c.detail for c in fails)
    for needle in ("no authentication", "ALES_REQUIRE_SIGNATURES", "ALES_SNAPSHOT_KEY", "SQLite",
                   "ALES_ENFORCE_WORKLOADS=off"):
        assert needle in text, needle
    assert rep.exit_code == 1


def test_development_defaults_warn_but_do_not_fail(tmp_path):
    rep = run_preflight({"ALES_TOKENS": TOKENS, "DATABASE_URL": _migrated_db(tmp_path)})
    assert rep.environment == "development" and rep.exit_code == 0
    assert status(rep, "production_rules") == WARN
    assert status(rep, "snapshot_key") == WARN
    assert status(rep, "unsafe_settings") == WARN
    assert status(rep, "purge") == WARN


def test_no_auth_anywhere_fails(tmp_path):
    rep = run_preflight({"DATABASE_URL": _migrated_db(tmp_path)})
    assert status(rep, "authentication") == FAIL and rep.exit_code == 1
    rep = run_preflight({"DATABASE_URL": _migrated_db(tmp_path), "ALES_DEV_ALLOW_ANONYMOUS": "1"})
    assert status(rep, "authentication") == WARN


def test_malformed_settings_fail_fast():
    rep = run_preflight({"ALES_ENV": "prod"})
    assert rep.exit_code == 1 and status(rep, "settings") == FAIL
    assert run_preflight({"ALES_PURGE_POLICY": "maybe"}).exit_code == 1


def test_snapshot_key_garbage_fails(tmp_path):
    rep = run_preflight({"ALES_TOKENS": TOKENS, "ALES_SNAPSHOT_KEY": "!!notbase64!!",
                         "DATABASE_URL": _migrated_db(tmp_path)})
    assert status(rep, "snapshot_key") == FAIL


def test_database_states(tmp_path):
    missing = f"sqlite:///{tmp_path / 'nope.db'}"
    rep = run_preflight({"ALES_TOKENS": TOKENS, "DATABASE_URL": missing})
    assert status(rep, "database") == WARN  # created + migrated at startup
    assert not (tmp_path / "nope.db").exists()  # preflight never creates it
    rep = run_preflight({"ALES_TOKENS": TOKENS, "DATABASE_URL": missing, "ALES_SKIP_STARTUP_MIGRATIONS": "1"})
    assert status(rep, "database") == FAIL
    # exists but unmigrated: WARN, or FAIL when startup migrations are skipped
    from ales_server.hardening import make_engine

    eng = make_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    eng.connect().close()
    eng.dispose()
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    assert status(run_preflight({"ALES_TOKENS": TOKENS, "DATABASE_URL": url}), "database") == WARN
    assert status(run_preflight({"ALES_TOKENS": TOKENS, "DATABASE_URL": url, "ALES_SKIP_STARTUP_MIGRATIONS": "1"}),
                  "database") == FAIL
    # unreachable server
    rep = run_preflight({"ALES_TOKENS": TOKENS, "DATABASE_URL": "postgresql+psycopg://u:p@127.0.0.1:1/db"})
    assert status(rep, "database") == FAIL
    assert "p@" not in rep.by_name("database").detail  # password never echoed


def test_denylist_and_audit_export_files(tmp_path):
    base = {"ALES_TOKENS": TOKENS, "DATABASE_URL": _migrated_db(tmp_path)}
    d = tmp_path / "deny.json"
    d.write_text(json.dumps({"subjects": ["a"], "jwt_jtis": ["j1", "j2"]}), encoding="utf-8")
    rep = run_preflight({**base, "ALES_DENYLIST_FILE": str(d)})
    # the authenticator itself reads the file: a good one passes and reports its contents
    assert status(rep, "denylist_file") == PASS and "2 jti" in rep.by_name("denylist_file").detail
    d.write_text("{nope", encoding="utf-8")
    rep = run_preflight({**base, "ALES_DENYLIST_FILE": str(d)})
    assert rep.exit_code == 1  # surfaces as an authentication-config FAIL (same loader as startup)
    rep = run_preflight({**base, "ALES_AUDIT_EXPORT_FILE": str(tmp_path / "no_such_dir" / "a.ndjson")})
    assert status(rep, "audit_export") == FAIL
    rep = run_preflight({**base, "ALES_AUDIT_EXPORT_FILE": str(tmp_path / "a.ndjson")})
    assert status(rep, "audit_export") == PASS


def test_workload_and_grant_modes(tmp_path):
    base = {"ALES_TOKENS": TOKENS, "DATABASE_URL": _migrated_db(tmp_path)}
    assert status(run_preflight({**base, "ALES_ENFORCE_WORKLOADS": "strict"}), "workloads") == PASS
    assert status(run_preflight({**base, "ALES_ENFORCE_WORKLOADS": "auto"}), "workloads") == WARN
    assert status(run_preflight({**base, "ALES_REQUIRE_GRANTS": "1"}), "grants") == PASS
    rep = run_preflight(good_prod(tmp_path, ALES_APPROVAL_ALLOW_SELF="1"))
    assert status(rep, "unsafe_settings") == FAIL


def test_json_and_table_rendering(tmp_path, capsys):
    env = good_prod(tmp_path)
    doc = run_preflight(env).to_dict()
    assert doc["ok"] is True and doc["environment"] == "production"
    assert {c["status"] for c in doc["checks"]} <= {PASS, WARN, FAIL}
    assert doc["counts"][FAIL] == 0
    table = run_preflight(env).render()
    assert "PASS" in table and "WARN" in table and "pass," in table


def test_cli_exit_codes_and_json(tmp_path):
    import os

    env = {**os.environ, **good_prod(tmp_path)}
    for k in ("ALES_DEV_ALLOW_ANONYMOUS",):
        env.pop(k, None)
    cmd = [sys.executable, "-m", "ales_server.preflight", "--json"]
    cwd = ROOT / "server"
    ok = subprocess.run(cmd, env={**env, "PYTHONPATH": f"{cwd}{os.pathsep}{ROOT / 'core'}"}, check=False, capture_output=True,
                        text=True, cwd=cwd)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert json.loads(ok.stdout)["ok"] is True
    bad = subprocess.run(cmd[:3], check=False, env={**env, "ALES_PURGE_POLICY": "purge", "PYTHONPATH": f"{cwd}{os.pathsep}{ROOT / 'core'}"},
                         capture_output=True, text=True, cwd=cwd)
    assert bad.returncode == 1 and "FAIL" in bad.stdout  # importing the package does NOT start/refuse the server


def test_main_returns_exit_code(monkeypatch, tmp_path, capsys):
    for k, v in good_prod(tmp_path).items():
        monkeypatch.setenv(k, v)
    assert preflight.main([]) == 0
    monkeypatch.setenv("ALES_PURGE_POLICY", "purge")
    assert preflight.main([]) == 1


@pytest.mark.parametrize("name", ["settings"])
def test_report_by_name_lookup(name):
    assert run_preflight({"ALES_ENV": "prod"}).by_name(name).status == FAIL
