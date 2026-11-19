"""Tiny thread-safe in-process counters + Prometheus text rendering (no third-party dependency).

Counters are per-process and per-tenant internally. An authenticated scrape (``read`` role) renders only
the caller's tenant; an unauthenticated scrape (``ALES_METRICS_PUBLIC=1``) renders the sum over all
tenants. With several replicas each one reports its own process; aggregating across replicas is the
scraper's job (Prometheus ``sum()``). Gauges derived from the database (outbox, audit, policy) are
read live and are therefore identical across replicas.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict


def _esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, str | None, str], int] = defaultdict(int)  # (name, tenant, label)
        self.started = time.monotonic()

    def inc(self, name: str, tenant: str | None, label: str = "", n: int = 1) -> None:
        with self._lock:
            self._counters[(name, tenant, label)] += n

    def snapshot(self, name: str, tenant: str | None) -> dict[str, int]:
        """``label -> count`` for ``name``; restricted to ``tenant`` unless it is None (all tenants)."""
        result: dict[str, int] = defaultdict(int)
        with self._lock:
            for (nm, t, label), v in self._counters.items():
                if nm == name and (tenant is None or t == tenant):
                    result[label] += v
        return dict(result)

    def uptime(self) -> float:
        return time.monotonic() - self.started


def render(
    m: Metrics,
    tenant: str | None,
    *,
    outbox_totals: dict[str, int],
    audit_records: int,
    active_policy: tuple[str, int] | None,
) -> str:
    lines: list[str] = []

    def family(name: str, help_: str, kind: str) -> None:
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} {kind}")

    family("ales_authorize_total", "Authorize decisions served by this process.", "counter")
    decisions = m.snapshot("authorize", tenant)
    for decision in sorted(decisions):
        lines.append(f'ales_authorize_total{{decision="{_esc(decision)}"}} {decisions[decision]}')
    family("ales_revocations_total", "Revocation events accepted by this process.", "counter")
    lines.append(f"ales_revocations_total {sum(m.snapshot('revocation', tenant).values())}")
    # process-wide (not tenant-scoped) operational counters
    family(
        "ales_denylist_rejections_total",
        "Requests rejected because the identity is on the denylist.",
        "counter",
    )
    lines.append(f"ales_denylist_rejections_total {sum(m.snapshot('denylist_rejection', None).values())}")
    family("ales_token_reloads_total", "ALES_TOKENS_FILE reload attempts by outcome.", "counter")
    reloads = m.snapshot("token_reload", None)
    for outcome in sorted(reloads):
        lines.append(f'ales_token_reloads_total{{outcome="{_esc(outcome)}"}} {reloads[outcome]}')
    family(
        "ales_audit_export_failures_total",
        "Audit records that failed to export to ALES_AUDIT_EXPORT_FILE.",
        "counter",
    )
    lines.append(f"ales_audit_export_failures_total {sum(m.snapshot('audit_export_failure', None).values())}")
    family("ales_outbox_rows", "Invalidation outbox rows by state.", "gauge")
    for state in sorted(outbox_totals):
        lines.append(f'ales_outbox_rows{{state="{_esc(state)}"}} {outbox_totals[state]}')
    family("ales_audit_records_total", "Audit ledger records.", "gauge")
    lines.append(f"ales_audit_records_total {audit_records}")
    if active_policy is not None:
        family("ales_policy_active_info", "Active policy document of the tenant.", "gauge")
        lines.append(
            f'ales_policy_active_info{{policy_id="{_esc(active_policy[0])}",version="{active_policy[1]}"}} 1'
        )
    family("ales_uptime_seconds", "Seconds since this process started.", "gauge")
    lines.append(f"ales_uptime_seconds {m.uptime():.3f}")
    return "\n".join(lines) + "\n"
