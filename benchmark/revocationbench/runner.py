"""Run the scenarios, print a table, and write latest.json / latest.md (latest-postgres.* for --profile postgres)."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import traceback
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ._paths import REPO_ROOT
from .harness import ScenarioResult
from .metrics import aggregate, scenario_metrics
from .remote import INFO, PROFILES, set_profile
from .scenarios import INPROCESS_ONLY, SCENARIOS

REPORTS_DIR = Path(__file__).resolve().parents[1] / "reports"

NOT_COVERED = [
    (
        "Uninstrumented paths: any read that does not call authorize (direct DB/cache/vector access, a model "
        "client without the wrapper) is outside the guarantee and is not exercised here. The cache scenario shows "
        "the physical entry still sits in the store after the block; only the guarded read path is protected."
    ),
    (
        "Physical purge timing is measured only in acl_revocation and source_deletion, against in-process "
        "stand-in stores (an in-memory vector index and a dict-backed redis-like cache) with the real purge "
        "handlers and outbox dispatcher. purge_completion_latency is driven by direct dispatcher.run_once calls, "
        "so it EXCLUDES the background worker's polling interval (default 5 s in a deployment) and real "
        "store/network latency, and does not exercise retries, backoff or dead letters. Reads are denied "
        "synchronously regardless of purge state; the other scenarios do not measure deletion."
    ),
    (
        "Multi-process decision-cache staleness: readers here share the revoking client, whose epoch-bound cache "
        "is invalidated on revocation. A reader in another process that did not itself observe the new epoch "
        "may serve a cached ALLOW until its next server contact or the cache TTL (default 30 s). That window "
        "follows from the design but is not measured by this suite."
    ),
    (
        "Information already seen: revocation cannot recall content a person or model has already received "
        "(spec non-guarantee); the benchmark only measures future reads."
    ),
    "Concurrency: benchmark scenarios run sequentially; in-flight revocation races and multi-process behavior are covered by the stress suite (stress/), not here. Multi-replica/LB and sustained load remain unmeasured.",
    (
        "Scale beyond two points: deep_lineage (chain of 100) and wide_fanout (1 source, 200 children) are the "
        "only scale points; beyond them, and for graphs with both depth and width, traversal cost is not "
        "characterized. Other scenarios use 6-object lineages."
    ),
    (
        "service_outage uses a simulated clock; its exposure window is the configured lease, reported separately "
        "as bounded-exposure reads, never silently folded into escapes or hidden."
    ),
    (
        "delayed_revocation: the server clock is shifted in-process (no sleeping) and the reader's wall clock "
        "moves with it, while its monotonic (TTL) clock is frozen, so cutover at effective_at is enforced by "
        "the response's valid_until bound alone. Not covered: a reader that cached an ALLOW BEFORE the "
        "future-dated event was accepted holds an entry with no valid_until and, if it never contacts the "
        "server, serves it until TTL (the multi-process staleness item above); clients with badly skewed "
        "wall clocks are protected only up to the cache's max_clock_skew allowance (default 30 s)."
    ),
    (
        "Adapter coverage beyond the cache GuardedCache scenario: the vector store, LangGraph and filesystem "
        "adapters are covered by the separate conformance suite, not by this benchmark."
    ),
]


PROFILE_NOT_COVERED = {
    "inprocess": (
        "Real network and database: the control plane runs in-process (FastAPI TestClient bridge, in-memory "
        "SQLite). Latencies exclude network hops, TLS, Postgres and multi-replica effects and are lower than a "
        "production deployment would see. Treat them as relative, not absolute. The postgres profile "
        "(`--profile postgres`, report latest-postgres.*) has real Postgres + loopback HTTP numbers."
    ),
    "postgres": (
        "Still not covered by the postgres profile: a single uvicorn process (one replica, no load balancer), "
        "loopback HTTP on one machine (no TLS, no cross-host or cross-region latency), one Postgres and one "
        "Redis container on the same host, and sequential single-client load (no sustained or concurrent "
        "traffic, no connection-pool pressure). service_outage and delayed_revocation need in-process tricks "
        "(transport kill, server clock shift) and always run on the in-process profile; the report marks each "
        "scenario's actual profile. The background outbox worker is disabled (ALES_OUTBOX_INTERVAL=0) and the "
        "harness drives the dispatcher, so purge timings exclude the worker poll interval; the vector purge "
        "target is still the in-memory stand-in (only Postgres and Redis are real)."
    ),
}


def git_rev() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        rev = out.stdout.strip()
        return rev or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def effective_profile(name: str, profile: str) -> str:
    """The profile a scenario actually runs on: in-process-only scenarios never leave it."""
    return "inprocess" if name in INPROCESS_ONLY else profile


def run_scenario(name: str, profile: str = "inprocess") -> ScenarioResult:
    info = INFO[effective_profile(name, profile)]
    set_profile(info.name)
    try:
        r = SCENARIOS[name]()
    except Exception as e:  # noqa: BLE001 - a crashing scenario is a failed scenario
        r = ScenarioResult(
            name=name,
            passed=False,
            escapes=0,
            details={"error": f"{type(e).__name__}: {e}", "traceback": traceback.format_exc()},
        )
    finally:
        set_profile("inprocess")
    r.profile, r.database, r.transport = info.name, info.database, info.transport
    return r


def run_all(names: Sequence[str] | None = None, profile: str = "inprocess") -> list[ScenarioResult]:
    return [run_scenario(n, profile) for n in (names or list(SCENARIOS))]


def build_report(results: Sequence[ScenarioResult], profile: str = "inprocess") -> dict[str, Any]:
    scenarios = []
    for r in results:
        scenarios.append(
            {
                "name": r.name,
                "profile": r.profile,
                "database": r.database,
                "transport": r.transport,
                "passed": r.passed,
                "escapes": r.escapes,
                "metrics": scenario_metrics(r),
                "details": r.details,
            }
        )
    by_profile: dict[str, list[str]] = {}
    for r in results:
        by_profile.setdefault(r.profile, []).append(r.name)
    not_covered = list(NOT_COVERED)
    not_covered.insert(3, PROFILE_NOT_COVERED[profile])
    return {
        "run_at": datetime.now(UTC).isoformat(),
        "git_rev": git_rev(),
        "profile": profile,
        "database": INFO[profile].database,
        "transport": INFO[profile].transport,
        "summary": {
            "requested_profile": profile,
            "scenarios_by_profile": by_profile,
            "inprocess_only_scenarios": sorted(INPROCESS_ONLY),
        },
        "scenarios": scenarios,
        "aggregate": aggregate(results),
        "not_covered": not_covered,
    }


def _fmt(x: float | None, nd: int = 2) -> str:
    return "n/a" if x is None else f"{x:.{nd}f}"


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.2f}%"


def table(report: dict[str, Any]) -> str:
    rows = [("scenario", "profile", "pass", "escapes", "attempted", "p95 ms")]
    for s in report["scenarios"]:
        m = s["metrics"]
        rows.append(
            (
                s["name"],
                s["profile"],
                "PASS" if s["passed"] else "FAIL",
                str(s["escapes"]),
                str(m["attempted_post_revocation_reads"]),
                _fmt(m["decision_overhead_ms"]["p95"]),
            )
        )
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(c.ljust(widths[i]) for i, c in enumerate(r)) for r in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def markdown(report: dict[str, Any]) -> str:
    agg = report["aggregate"]
    pc = agg["purge_completion_latency_ms"]
    ov, ovs, lat = (
        agg["decision_overhead_ms"],
        agg["decision_overhead_server_roundtrip_ms"],
        agg["revocation_to_deny_latency_ms"],
    )
    out = [
        f"# RevocationBench latest run ({report['profile']} profile: {report['database']}, {report['transport']})",
        "",
        (
            f"Run at `{report['run_at']}` against git revision `{report['git_rev']}`. "
            "Generated by `python -m revocationbench`; do not hand-edit."
        ),
        "",
        "## Result",
        "",
        (
            f"{agg['scenarios_passed']}/{agg['scenarios_run']} scenarios passed. "
            f"**{agg['escapes']} escapes** in {agg['attempted_post_revocation_reads']} post-revocation read attempts."
        ),
        "",
        "| scenario | profile | database | transport | pass | escapes | post-revocation reads | legit reads | false blocks | p95 decision ms | purge ms |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for s in report["scenarios"]:
        m = s["metrics"]
        out.append(
            f"| {s['name']} | {s['profile']} | {s['database']} | {s['transport']} | "
            f"{'PASS' if s['passed'] else 'FAIL'} | {s['escapes']} | "
            f"{m['attempted_post_revocation_reads']} | {m['legitimate_reads']} | {m['false_blocks']} | "
            f"{_fmt(m['decision_overhead_ms']['p95'])} | {_fmt(m['purge_completion_latency_ms']['p50'])} |"
        )
    out += [
        "",
        "Profile per scenario: "
        + "; ".join(f"{p}: {', '.join(n)}" for p, n in report["summary"]["scenarios_by_profile"].items())
        + (
            f". Always in-process (need an in-process trick): {', '.join(report['summary']['inprocess_only_scenarios'])}."
            if report["profile"] != "inprocess"
            else "."
        ),
        "",
        "## Aggregate metrics",
        "",
        "| metric | value |",
        "|---|---|",
        f"| stale_context_escape_rate | {_pct(agg['stale_context_escape_rate'])} ({agg['escapes']}/{agg['attempted_post_revocation_reads']}) |",
        f"| false_block_rate | {_pct(agg['false_block_rate'])} ({agg['false_blocks']}/{agg['legitimate_reads']}) |",
        f"| lineage_completeness | {_pct(agg['lineage_completeness'])} ({agg['derivatives_audited']} derivatives audited) |",
        f"| revocation_to_deny_latency p50 / p95 / max | {_fmt(lat['p50'])} / {_fmt(lat['p95'])} / {_fmt(lat['max'])} ms (n={lat['count']}) |",
        f"| purge_completion_latency p50 / p95 / max | {_fmt(pc['p50'])} / {_fmt(pc['p95'])} / {_fmt(pc['max'])} ms (n={pc['count']}; excludes worker poll interval) |",
        f"| decision_overhead p50 / p95 / p99 (all authorize calls) | {_fmt(ov['p50'])} / {_fmt(ov['p95'])} / {_fmt(ov['p99'])} ms (n={ov['count']}) |",
        f"| decision_overhead p50 / p95 / p99 (server round trips only) | {_fmt(ovs['p50'])} / {_fmt(ovs['p95'])} / {_fmt(ovs['p99'])} ms (n={ovs['count']}) |",
        f"| bounded_exposure_reads (within published lease, not escapes) | {agg['bounded_exposure_reads']} |",
        "",
        (
            "Definitions: an *escape* is a read that returned usable content although an ancestor was revoked "
            "(or the object belongs to another tenant). *revocation_to_deny_latency* is measured from the moment "
            "the revocation call returned (event accepted) to the completion of the first denied read. "
            "*decision_overhead* is the wall-clock time of each `authorize` call as the caller sees it; calls "
            "answered from the client's epoch-bound decision cache are included in the first row and excluded "
            "from the second. *purge_completion_latency* runs from revocation acceptance until every outbox row "
            "handled by a purge handler (all descendants) is `done` and the objects are gone from the raw stores. "
            "A false block is a legitimate read by an authorized principal that was denied."
        ),
        "",
        "## Scenario notes",
        "",
    ]
    for s in report["scenarios"]:
        out.append(f"### {s['name']}")
        out.append("")
        d = s["details"]
        if "error" in d:
            out.append(f"Crashed: `{d['error']}`")
        failed = d.get("failed_checks") or []
        out.append(
            f"{len(d.get('checks', []))} checks, {len(failed)} failed."
            + (f" Failed: {failed}" if failed else "")
        )
        extras = {k: v for k, v in d.items() if k not in ("checks", "failed_checks", "error", "traceback")}
        for k, v in extras.items():
            out.append(f"- {k}: {v}")
        out.append("")
    out += ["## What is NOT covered", ""]
    out += [f"- {x}" for x in report["not_covered"]]
    out.append("")
    return "\n".join(out)


def report_stem(profile: str) -> str:
    return "latest" if profile == "inprocess" else f"latest-{profile}"


def write_reports(report: dict[str, Any], out_dir: Path | None = None) -> tuple[Path, Path]:
    out_dir = out_dir or REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = report_stem(report.get("profile", "inprocess"))
    jp, mp = out_dir / f"{stem}.json", out_dir / f"{stem}.md"
    jp.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    mp.write_text(markdown(report), encoding="utf-8")
    return jp, mp


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="revocationbench", description="ALES INVARIANT revocation benchmark")
    ap.add_argument("--scenario", "-s", action="append", choices=list(SCENARIOS), help="run only these")
    ap.add_argument(
        "--profile",
        choices=list(PROFILES),
        default="inprocess",
        help="inprocess (TestClient + in-memory SQLite, default) or postgres (uvicorn subprocess + Postgres + Redis; "
        "needs BENCH_POSTGRES_URL and BENCH_REDIS_URL)",
    )
    ap.add_argument("--out", type=Path, default=None, help="report directory (default benchmark/reports)")
    ap.add_argument("--no-write", action="store_true", help="do not write reports")
    args = ap.parse_args(argv)

    results = run_all(args.scenario, args.profile)
    report = build_report(results, args.profile)
    print(table(report))
    agg = report["aggregate"]
    print(
        f"\nescapes={agg['escapes']}/{agg['attempted_post_revocation_reads']}  "
        f"false_blocks={agg['false_blocks']}/{agg['legitimate_reads']}  "
        f"lineage_completeness={_pct(agg['lineage_completeness'])}  "
        f"overhead p95={_fmt(agg['decision_overhead_ms']['p95'])} ms  "
        f"revoke->deny p95={_fmt(agg['revocation_to_deny_latency_ms']['p95'])} ms  "
        f"purge max={_fmt(agg['purge_completion_latency_ms']['max'])} ms"
    )
    if not args.no_write:
        jp, mp = write_reports(report, args.out)
        print(f"wrote {jp}\nwrote {mp}")
    ok = all(r.passed for r in results) and agg["escapes"] == 0
    if not ok:
        for r in results:
            if not r.passed:
                print(
                    f"FAILED {r.name}: {r.details.get('failed_checks') or r.details.get('error')}",
                    file=sys.stderr,
                )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
