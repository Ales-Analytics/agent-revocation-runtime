import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from revocationbench.harness import BenchEnv
from revocationbench.metrics import aggregate, percentile
from revocationbench.runner import build_report, main, run_scenario, write_reports
from revocationbench.scenarios import SCENARIOS


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


def test_eight_families_present():
    assert set(SCENARIOS) == {
        "acl_revocation",
        "source_deletion",
        "version_supersession",
        "poisoned_source",
        "cache_replay",
        "agent_handoff",
        "multi_tenant_collision",
        "service_outage",
    }


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
