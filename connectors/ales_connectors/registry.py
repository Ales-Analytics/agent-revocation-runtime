"""ConnectorRegistry: the single entry point a scheduler/cron calls (``run_all_once``)."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .spi import ConnectorHealth, Envelope, RevocationEvent, SourceConnector


class StaleConnectorError(RuntimeError):
    """Raised by ``assert_fresh`` when one or more connectors are stale, failed, or never synced."""

    def __init__(self, stale: dict[str, str]) -> None:
        self.stale = dict(stale)  # connector_id -> reason
        self.connector_ids = sorted(stale)
        detail = "; ".join(f"{cid} ({why})" for cid, why in sorted(stale.items()))
        super().__init__(f"stale connectors: {detail}")


@dataclass(frozen=True)
class FreshnessPolicy:
    """Maximum tolerated sync lag. ``overrides`` maps connector_id -> its own max lag in seconds."""

    max_lag_seconds: float
    overrides: dict[str, float] = field(default_factory=dict)

    def limit_for(self, connector_id: str) -> float:
        return self.overrides.get(connector_id, self.max_lag_seconds)


@dataclass
class RunResult:
    connector_id: str
    ok: bool
    registered: list[Envelope] = field(default_factory=list)
    events: list[RevocationEvent] = field(default_factory=list)
    error: str | None = None


class ConnectorRegistry:
    def __init__(
        self, *, clock: Callable[[], float] = time.time, freshness: FreshnessPolicy | None = None
    ) -> None:
        self.freshness = freshness
        self._connectors: dict[str, SourceConnector] = {}
        self._clock = clock
        self._last_errors: dict[str, str] = {}

    def register(self, connector: SourceConnector, connector_id: str | None = None) -> None:
        context_id = connector_id or connector.connector_id
        if context_id in self._connectors:
            raise ValueError(f"connector {context_id!r} already registered")
        self._connectors[context_id] = connector

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
        for context_id in self.ids():
            c = self._connectors[context_id]
            try:
                registered = c.scan()
                events = c.watch_once()
            except Exception as exc:  # noqa: BLE001 - isolation boundary: any connector failure is reported
                message = f"{type(exc).__name__}: {exc}"
                self._last_errors[context_id] = message
                results.append(RunResult(context_id, False, error=message))
            else:
                self._last_errors.pop(context_id, None)
                results.append(RunResult(context_id, True, registered, events))
        return results

    def stale_connectors(
        self, connector_ids: Iterable[str] | None = None, *, policy: FreshnessPolicy | None = None
    ) -> dict[str, str]:
        """Return ``{connector_id: reason}`` for connectors that are not fresh under ``policy``.

        Stale means: last run failed, never synced (polling mode, or any mode when a policy is set), or
        ``lag_seconds`` above the policy limit. Without a policy (argument or registry default) the limit
        is ``3 x freshness_sla_seconds`` per connector (the ``health_report`` rule). Unknown ids are
        reported stale (fail closed).
        """
        policy_result = policy or self.freshness
        ids = self.ids() if connector_ids is None else list(connector_ids)
        result: dict[str, str] = {}
        for context_id in ids:
            connection = self._connectors.get(context_id)
            if connection is None:
                result[context_id] = "unknown connector"
                continue
            if context_id in self._last_errors:
                result[context_id] = f"last run failed: {self._last_errors[context_id]}"
                continue
            h = connection.health()
            if h.last_sync is None:
                if h.mode == "polling" or policy_result is not None:
                    result[context_id] = "never synced"
                continue
            if policy_result is not None:
                limit: float | None = policy_result.limit_for(context_id)
            else:
                limit = 3.0 * h.freshness_sla_seconds if h.freshness_sla_seconds else None
            enforced = policy_result is not None or h.mode == "polling"
            if enforced and limit is not None and h.lag_seconds is not None and h.lag_seconds > limit:
                result[context_id] = f"lag {h.lag_seconds:.0f}s exceeds {limit:.0f}s"
        return result

    def assert_fresh(
        self, connector_ids: Iterable[str] | None = None, *, policy: FreshnessPolicy | None = None
    ) -> None:
        """Raise ``StaleConnectorError`` (listing ids) if any selected connector is not fresh."""
        stale = self.stale_connectors(connector_ids, policy=policy)
        if stale:
            raise StaleConnectorError(stale)

    def health_report(self, *, stale_factor: float = 3.0) -> dict[str, Any]:
        """Aggregate health. status: ok | degraded (errors/stale/never synced) ."""
        conns: dict[str, dict[str, Any]] = {}
        worst_lag: float | None = None
        degraded: list[str] = []
        coverage: dict[str, bool] = {}
        for context_id in self.ids():
            h: ConnectorHealth = self._connectors[context_id].health()
            d = h.as_dict()
            problems = []
            if context_id in self._last_errors:
                problems.append(f"last run failed: {self._last_errors[context_id]}")
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
            conns[context_id] = d
            if problems:
                degraded.append(context_id)
            if h.lag_seconds is not None:
                worst_lag = h.lag_seconds if worst_lag is None else max(worst_lag, h.lag_seconds)
            for event, ok in h.coverage.items():
                coverage[event] = coverage.get(event, True) and ok
        return {
            "status": "degraded" if degraded else "ok",
            "generated_at": self._clock(),
            "connector_count": len(conns),
            "degraded": degraded,
            "worst_lag_seconds": worst_lag,
            "coverage": coverage,  # event_type -> True only if EVERY connector covers it
            "connectors": conns,
        }


def freshness_guard(
    registry: ConnectorRegistry,
    connector_ids: Iterable[str] | None = None,
    *,
    policy: FreshnessPolicy | None = None,
) -> Callable[[], list[str]]:
    """Build a retrieval-path hook. Call the returned callable BEFORE serving source-derived answers.

    It returns the sorted list of stale connector ids; an empty list means fresh. The caller decides the
    response (deny, degrade, or refuse to serve), e.g.::

        guard = freshness_guard(registry, ["s3:docs/"], policy=FreshnessPolicy(300))
        if guard():
            raise PermissionError("source freshness not guaranteed")

    ``connector_ids`` is captured at build time (None = every connector registered at call time).
    """
    ids = None if connector_ids is None else list(connector_ids)

    def _guard() -> list[str]:
        return sorted(registry.stale_connectors(ids, policy=policy))

    return _guard
