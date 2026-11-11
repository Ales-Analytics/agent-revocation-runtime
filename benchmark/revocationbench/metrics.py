"""Metric computation for RevocationBench (per scenario and aggregate)."""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

from .harness import ScenarioResult


def percentile(values: Sequence[float], q: float) -> float | None:
    """Linear-interpolated percentile, q in [0, 100]. None for an empty sample."""
    if not values:
        return None
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    pos = (len(s) - 1) * q / 100.0
    lo, hi = math.floor(pos), math.ceil(pos)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def _r(x: float | None) -> float | None:
    return None if x is None else round(x, 4)


def summarize(values: Sequence[float]) -> dict[str, Any]:
    return {
        "count": len(values),
        "p50": _r(percentile(values, 50)),
        "p95": _r(percentile(values, 95)),
        "p99": _r(percentile(values, 99)),
        "max": _r(max(values)) if values else None,
    }


def _rate(num: int, den: int) -> float | None:
    return None if den == 0 else num / den


def scenario_metrics(r: ScenarioResult) -> dict[str, Any]:
    return {
        "attempted_post_revocation_reads": r.attempted,
        "escapes": r.escapes,
        "stale_context_escape_rate": _rate(r.escapes, r.attempted),
        "legitimate_reads": r.legit_reads,
        "false_blocks": r.false_blocks,
        "false_block_rate": _rate(r.false_blocks, r.legit_reads),
        "bounded_exposure_reads": r.bounded_exposure_reads,
        "decision_overhead_ms": summarize(r.timings.get("authorize_ms", [])),
        "decision_overhead_server_roundtrip_ms": summarize(r.timings.get("authorize_server_ms", [])),
        "revocation_accept_ms": summarize(r.timings.get("revocation_ms", [])),
        "revocation_to_deny_ms": summarize(r.timings.get("revocation_to_deny_ms", [])),
        "lineage_completeness": _rate(r.derivatives_complete, r.derivatives),
    }


def aggregate(results: Sequence[ScenarioResult]) -> dict[str, Any]:
    def pool(key: str) -> list[float]:
        return [v for r in results for v in r.timings.get(key, [])]

    attempted = sum(r.attempted for r in results)
    escapes = sum(r.escapes for r in results)
    legit = sum(r.legit_reads for r in results)
    fb = sum(r.false_blocks for r in results)
    deriv = sum(r.derivatives for r in results)
    complete = sum(r.derivatives_complete for r in results)
    return {
        "scenarios_run": len(results),
        "scenarios_passed": sum(1 for r in results if r.passed),
        "attempted_post_revocation_reads": attempted,
        "escapes": escapes,
        "stale_context_escape_rate": _rate(escapes, attempted),
        "legitimate_reads": legit,
        "false_blocks": fb,
        "false_block_rate": _rate(fb, legit),
        "bounded_exposure_reads": sum(r.bounded_exposure_reads for r in results),
        "revocation_to_deny_latency_ms": summarize(pool("revocation_to_deny_ms")),
        "revocation_accept_ms": summarize(pool("revocation_ms")),
        "decision_overhead_ms": summarize(pool("authorize_ms")),
        "decision_overhead_server_roundtrip_ms": summarize(pool("authorize_server_ms")),
        "lineage_completeness": _rate(complete, deriv),
        "derivatives_audited": deriv,
    }
