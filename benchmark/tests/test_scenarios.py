import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from revocationbench.harness import BenchEnv
from revocationbench.metrics import aggregate, percentile
from revocationbench.remote import active_profile, set_profile
from revocationbench.runner import (
    build_report,
    effective_profile,
    main,
    run_scenario,
    write_reports,
)
from revocationbench.scenarios import INPROCESS_ONLY, SCENARIOS


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_scenario_passes_with_zero_escapes(name):
    r = run_scenario(name)
    assert "error" not in r.details, r.details.get("traceback")
    assert r.escapes == 0, r.details["failed_checks"]
    assert r.false_blocks == 0
    assert r.attempted > 0 and r.legit_reads > 0
    assert r.passed, r.details["failed_checks"]
    assert r.derivatives > 0 and r.derivatives_complete == r.derivatives
    assert r.timings["authorize_ms"]


def test_thirteen_families_present():
    assert set(SCENARIOS) == {
        "acl_revocation",
        "source_deletion",
        "version_supersession",
        "poisoned_source",
        "cache_replay",
        "agent_handoff",
        "multi_tenant_collision",
        "service_outage",
        "delayed_revocation",
        "scoped_revocation",
        "signed_ingress",
        "deep_lineage",
        "wide_fanout",
    }
    assert len(SCENARIOS) == 13


def test_escape_is_counted_and_fails_the_scenario():
    """Canary: the accounting must actually register a leak (a bypass read that returns content)."""
    with BenchEnv() as env:
        lin = env.build_lineage("leaky")
        env.read_legit(lin.chunk["context_id"], {"type": "user", "id": "u"})
        env.revoke(lin.source, "deleted")
        env.record_revoked(True)  # simulate an uninstrumented read that returned content
        res = env.finish("canary")
    assert res.escapes == 1 and not res.passed


def test_false_block_is_counted_and_fails_the_scenario():
    with BenchEnv() as env:
        lin = env.build_lineage("over")
        env.revoke(lin.source, "deleted")
        env.read_revoked(lin.chunk["context_id"], {"type": "user", "id": "u"})
        env.read_legit(lin.chunk["context_id"], {"type": "user", "id": "u"})  # wrongly "legit": denied
        res = env.finish("canary2")
    assert res.false_blocks == 1 and not res.passed


def test_percentile():
    assert percentile([], 50) is None
    assert percentile([5.0], 99) == 5.0
    assert percentile([1, 2, 3, 4], 50) == 2.5
    assert percentile(list(range(101)), 95) == 95


def test_report_roundtrip_and_aggregate(tmp_path):
    results = [run_scenario("poisoned_source"), run_scenario("cache_replay")]
    report = build_report(results)
    assert set(report) >= {"run_at", "git_rev", "scenarios", "aggregate"}
    agg = aggregate(results)
    assert agg["escapes"] == 0 and agg["stale_context_escape_rate"] == 0
    assert agg["false_block_rate"] == 0 and agg["lineage_completeness"] == 1
    assert agg["revocation_to_deny_latency_ms"]["count"] >= 2
    jp, mp = write_reports(report, tmp_path)
    assert json.loads(jp.read_text())["aggregate"]["scenarios_run"] == 2
    assert "What is NOT covered" in mp.read_text()


def test_cli_exit_code(tmp_path, capsys):
    assert main(["-s", "poisoned_source", "--out", str(tmp_path)]) == 0
    assert "poisoned_source" in capsys.readouterr().out


def _checks(name):
    r = run_scenario(name)
    return r, {c["check"]: c["passed"] for c in r.details["checks"]}


def test_delayed_revocation_allows_before_and_denies_after_effective_at():
    r, checks = _checks("delayed_revocation")
    assert r.passed and r.escapes == 0
    assert checks["future-dated event accepted"]
    assert all(v for k, v in checks.items() if k.startswith("before effective_at"))
    assert all(v for k, v in checks.items() if k.startswith("after effective_at"))
    # escapes are only ever counted for the post-effectiveness reads (6 objects in the lineage)
    assert r.attempted == 6 and r.legit_reads > r.attempted


def test_scoped_revocation_denies_in_scope_only_then_unscoped_denies_all():
    r, checks = _checks("scoped_revocation")
    assert r.passed and r.escapes == 0 and r.false_blocks == 0
    assert all(
        checks[f"user-7 still ALLOW on {k}"]
        for k in ("source", "chunk", "embedding", "summary", "memory", "cache")
    )
    assert any(k.startswith("user-7 denied") and v for k, v in checks.items())
    # 6 in-scope denials + 12 after the unscoped event; user-7's earlier allows are not escapes
    assert r.attempted == 18


def test_signed_ingress_rejects_unsigned_and_enforces_signed():
    r, checks = _checks("signed_ingress")
    assert r.passed and r.escapes == 0
    assert checks["unsigned source rejected"] and checks["unsigned revocation rejected"]
    assert checks["tampered signed source rejected"]
    assert all(v for k, v in checks.items() if k.startswith("signed revocation"))


def test_multi_tenant_binding_is_403():
    r, checks = _checks("multi_tenant_collision")
    assert r.passed
    for k in ("register into", "revoke in", "authorize in"):
        assert checks[next(c for c in checks if c.startswith(f"tenant-b token cannot {k}"))]


def test_profile_plumbing_inprocess(tmp_path):
    # in-process-only scenarios never leave the in-process profile, even when postgres is requested
    assert INPROCESS_ONLY == {"service_outage", "delayed_revocation"} and INPROCESS_ONLY <= set(SCENARIOS)
    assert effective_profile("service_outage", "postgres") == "inprocess"
    assert effective_profile("acl_revocation", "postgres") == "postgres"
    assert effective_profile("acl_revocation", "inprocess") == "inprocess"

    r = run_scenario("poisoned_source")
    assert (r.profile, r.database, r.transport) == ("inprocess", "sqlite-inmem", "inprocess")
    assert active_profile() == "inprocess"  # run_scenario restores the default
    report = build_report([r])
    s0 = report["scenarios"][0]
    assert (s0["profile"], s0["database"], s0["transport"]) == ("inprocess", "sqlite-inmem", "inprocess")
    assert report["profile"] == "inprocess"
    assert report["summary"]["scenarios_by_profile"] == {"inprocess": ["poisoned_source"]}
    jp, _ = write_reports(report, tmp_path)
    assert jp.name == "latest.json"
    pg = build_report([r], "postgres")
    assert write_reports(pg, tmp_path)[0].name == "latest-postgres.json"

    with pytest.raises(ValueError):
        set_profile("mysql")


def test_postgres_profile_requires_env(monkeypatch):
    monkeypatch.delenv("BENCH_POSTGRES_URL", raising=False)
    r = run_scenario("poisoned_source", "postgres")
    assert not r.passed and "BENCH_POSTGRES_URL" in r.details["error"]
    assert active_profile() == "inprocess"
