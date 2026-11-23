from dataclasses import replace

from ales_adapters.coverage import manifest_report
from ales_conformance.contract import ConformanceReport
from ales_conformance.report import UNVERIFIED, VERIFIED, render_markdown, verify_manifests
from ales_conformance.suite import run_all


def _states(reports):
    return {m.adapter: s for m, s in verify_manifests(manifest_report(), reports)}


def test_retrieval_claims_verified_by_passing_runs():
    reports = run_all(include_live=False)
    st = _states(reports)
    for name in ("vector_store_inmemory", "llamaindex", "acs", "langgraph_middleware"):
        assert st[name] == VERIFIED, name
    # no contract row (portable pgvector) or live row absent -> UNVERIFIED, never silently verified
    assert st["pgvector_portable"] == UNVERIFIED
    assert st["qdrant"] == UNVERIFIED
    assert st["redis_cache"] == UNVERIFIED
    assert st["model_gateway"] == "n/a"


def test_failing_run_marks_claim_unverified():
    reports = run_all(include_live=False)
    cache = next(r for r in reports if r.adapter == "GuardedCache (DictRedis)")
    live = replace(cache, adapter="GuardedCache (Redis, live)", store="live store")
    assert _states([*reports, live])["redis_cache"] == VERIFIED
    broken = [*reports, replace(live, passed=False)]
    assert isinstance(broken[0], ConformanceReport)
    assert _states(broken)["redis_cache"] == UNVERIFIED
    assert _states([])["acs"] == UNVERIFIED


def test_report_contains_manifest_section():
    text = render_markdown(run_all(include_live=False))
    assert "## Capability manifests" in text
    line = next(ln for ln in text.splitlines() if ln.startswith("| qdrant |"))
    assert line.endswith("| UNVERIFIED |")
    assert next(ln for ln in text.splitlines() if ln.startswith("| llamaindex |")).endswith("| VERIFIED |")
