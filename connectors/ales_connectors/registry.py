"""ConnectorRegistry: the single entry point a scheduler/cron calls (``run_all_once``)."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .spi import ConnectorHealth, Envelope, RevocationEvent, SourceConnector


@dataclass
class RunResult:
    connector_id: str
    ok: bool
    registered: list[Envelope] = field(default_factory=list)
    events: list[RevocationEvent] = field(default_factory=list)
    error: str | None = None


class ConnectorRegistry:
    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._connectors: dict[str, SourceConnector] = {}
        self._clock = clock
        self._last_errors: dict[str, str] = {}

    def register(self, connector: SourceConnector, connector_id: str | None = None) -> None:
        cid = connector_id or connector.connector_id
        if cid in self._connectors:
            raise ValueError(f"connector {cid!r} already registered")
        self._connectors[cid] = connector

    def get(self, connector_id: str) -> SourceConnector:
        return self._connectors[connector_id]

    def ids(self) -> list[str]:
        return sorted(self._connectors)

    def run_all_once(self) -> list[RunResult]:
        """scan() then watch_once() on every connector. One connector failing never stops the others.

        A failed connector is reported ``ok=False`` and shows up in ``health_report``; it is never silently
        skipped, because a connector that cannot sync is a revocation blind spot.
        """
        results: list[RunResult] = []
        for cid in self.ids():
            c = self._connectors[cid]
            try:
                registered = c.scan()
                events = c.watch_once()
            except Exception as exc:  # noqa: BLE001 - isolation boundary: any connector failure is reported
                msg = f"{type(exc).__name__}: {exc}"
                self._last_errors[cid] = msg
                results.append(RunResult(cid, False, error=msg))
            else:
                self._last_errors.pop(cid, None)
                results.append(RunResult(cid, True, registered, events))
        return results

    def health_report(self, *, stale_factor: float = 3.0) -> dict[str, Any]:
        """Aggregate health. status: ok | degraded (errors/stale/never synced) ."""
        conns: dict[str, dict[str, Any]] = {}
        worst_lag: float | None = None
        degraded: list[str] = []
        coverage: dict[str, bool] = {}
        for cid in self.ids():
            h: ConnectorHealth = self._connectors[cid].health()
            d = h.as_dict()
            problems = []
            if cid in self._last_errors:
                problems.append(f"last run failed: {self._last_errors[cid]}")
            if h.last_sync is None and h.mode == "polling":
                problems.append("never synced")
            if (
                h.mode == "polling"
                and h.lag_seconds is not None
                and h.freshness_sla_seconds
                and h.lag_seconds > stale_factor * h.freshness_sla_seconds
            ):
                problems.append("stale: lag exceeds freshness SLA")
            d["problems"] = problems
            conns[cid] = d
            if problems:
                degraded.append(cid)
            if h.lag_seconds is not None:
                worst_lag = h.lag_seconds if worst_lag is None else max(worst_lag, h.lag_seconds)
            for ev, ok in h.coverage.items():
                coverage[ev] = coverage.get(ev, True) and ok
        return {
            "status": "degraded" if degraded else "ok",
            "generated_at": self._clock(),
            "connector_count": len(conns),
            "degraded": degraded,
            "worst_lag_seconds": worst_lag,
            "coverage": coverage,  # event_type -> True only if EVERY connector covers it
            "connectors": conns,
        }
