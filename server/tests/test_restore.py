"""R22: export / verify / reapply tooling against a point-in-time restore that resurrects a revoked source."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
from ales_server import create_app
from fastapi.testclient import TestClient
from server_helpers import T1, TOKENS, authorize_body, chain

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import ales_restore_check as rc


def _client(path: Path) -> TestClient:
    tc = TestClient(create_app(f"sqlite:///{path}", tokens=TOKENS, outbox_interval=0), headers=dict(T1))
    tc.__enter__()
    return tc


def _decision(tc: TestClient, ctx: str) -> str:
    r = tc.post("/v1/authorize", json=authorize_body("t1", ctx))
    assert r.status_code == 200, r.text
    return r.json()["decision"]


@pytest.fixture
def scenario(tmp_path):
    """live DB with a registered chain; a backup copy taken BEFORE the revocation; the revocation applied."""
    live = tmp_path / "live.db"
    backup = tmp_path / "backup.db"
    tc = _client(live)
    src, chunk, summ = chain()
    for env, path in ((src, "sources"), (chunk, "derivations"), (summ, "derivations")):
        assert tc.post(f"/v1/{path}", json=env).status_code == 200
    assert _decision(tc, summ["context_id"]) == "ALLOW"
    shutil.copy(live, backup)  # the "last good backup"
    r = tc.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"})
    assert r.status_code == 200
    assert _decision(tc, summ["context_id"]) == "DENY"
    export = tmp_path / "export.jsonl"
    rc_code = rc.main(["--database-url", f"sqlite:///{live}", "export", "--out", str(export)])
    assert rc_code == 0
    tc.__exit__(None, None, None)
    restored = tmp_path / "restored.db"
    shutil.copy(backup, restored)  # restore to before the revocation
    return {"summ": summ["context_id"], "export": export, "restored": restored, "live": live, "src": src}


def test_export_contains_events_tombstones_and_epoch(scenario):
    recs = [json.loads(x) for x in scenario["export"].read_text().splitlines()]
    types = [r["type"] for r in recs]
    assert types.count("revocation_event") == 1
    assert types.count("tombstone") >= 1
    epoch = next(r for r in recs if r["type"] == "epoch")
    assert epoch["tenant_id"] == "t1" and epoch["revocation_epoch"] == 1


def test_restore_resurrects_then_verify_detects_then_reapply_denies(scenario, capsys):
    url = f"sqlite:///{scenario['restored']}"
    tc = _client(scenario["restored"])
    try:
        # the hazard: the restored database forgot the revocation
        assert _decision(tc, scenario["summ"]) == "ALLOW"
        capsys.readouterr()
        assert rc.main(["--database-url", url, "verify", "--file", str(scenario["export"])]) == 1
        gaps = json.loads(capsys.readouterr().out)
        assert gaps["ok"] is False
        assert len(gaps["missing_events"]) == 1
        assert gaps["epoch_behind"] == [{"tenant_id": "t1", "file_epoch": 1, "db_epoch": 0}]

        assert rc.main(["--database-url", url, "reapply", "--file", str(scenario["export"])]) == 0
        report = json.loads(capsys.readouterr().out)
        assert (
            report["ok"] is True
            and len(report["reapplied"]) == 1
            and report["remaining_gaps"]["missing_events"] == []
        )

        assert rc.main(["--database-url", url, "verify", "--file", str(scenario["export"])]) == 0
        capsys.readouterr()
        assert (
            _decision(tc, scenario["summ"]) == "DENY"
        )  # revocation is back in force (shared DB, no restart)
    finally:
        tc.__exit__(None, None, None)


def test_reapply_is_idempotent(scenario, capsys):
    url = f"sqlite:///{scenario['restored']}"
    args = ["--database-url", url, "reapply", "--file", str(scenario["export"])]
    assert rc.main(args) == 0
    capsys.readouterr()
    assert rc.main(args) == 0
    again = json.loads(capsys.readouterr().out)
    assert again["reapplied"] == [] and again["already_present"] == 1
    with rc._make_session_factory(url)() as s:
        assert (
            next(r for r in rc.export_records(s) if r["type"] == "epoch")["revocation_epoch"] == 1
        )  # not double-bumped


def test_reapply_from_audit_export_file(scenario, tmp_path, capsys):
    """The ALES_AUDIT_EXPORT_FILE flavour carries revocation.accept records; those suffice."""
    live = tmp_path / "live2.db"
    audit_file = tmp_path / "audit.jsonl"
    tc = TestClient(
        create_app(
            f"sqlite:///{live}",
            tokens=TOKENS,
            outbox_interval=0,
            env={"ALES_AUDIT_EXPORT_FILE": str(audit_file)},
        ),
        headers=dict(T1),
    )
    with tc:
        src, chunk, summ = chain()
        for env, path in ((src, "sources"), (chunk, "derivations"), (summ, "derivations")):
            assert tc.post(f"/v1/{path}", json=env).status_code == 200
        backup = tmp_path / "backup2.db"
        shutil.copy(live, backup)
        assert (
            tc.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"}).status_code
            == 200
        )
    url = f"sqlite:///{backup}"
    capsys.readouterr()
    assert rc.main(["--database-url", url, "verify", "--file", str(audit_file)]) == 1
    capsys.readouterr()
    assert rc.main(["--database-url", url, "reapply", "--file", str(audit_file)]) == 0
    tc2 = _client(backup)
    try:
        assert _decision(tc2, summ["context_id"]) == "DENY"
    finally:
        tc2.__exit__(None, None, None)


def test_verify_clean_database_passes(scenario, capsys):
    capsys.readouterr()
    assert (
        rc.main(
            ["--database-url", f"sqlite:///{scenario['live']}", "verify", "--file", str(scenario["export"])]
        )
        == 0
    )


def test_input_and_usage_errors(tmp_path, capsys, monkeypatch):
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{not json\n")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert rc.main(["verify", "--file", str(bad)]) == 2  # no DATABASE_URL
    assert rc.main(["--database-url", f"sqlite:///{tmp_path / 'x.db'}", "verify", "--file", str(bad)]) == 2
    assert (
        rc.main(
            ["--database-url", f"sqlite:///{tmp_path / 'x.db'}", "verify", "--file", str(tmp_path / "none")]
        )
        == 2
    )
