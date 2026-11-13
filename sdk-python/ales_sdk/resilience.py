"""Circuit breaker guarding the decision API transport.

After ``failure_threshold`` consecutive transport failures the breaker OPENs and callers fail fast
(no network traffic) for ``recovery_timeout`` seconds. It then goes HALF_OPEN and admits exactly one
probe request: success closes the breaker, failure re-opens it for another recovery period.
"""

from __future__ import annotations

import enum
import threading
import time
from collections.abc import Callable

__all__ = ["BreakerState", "CircuitBreaker"]


class BreakerState(str, enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 10.0,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if recovery_timeout < 0:
            raise ValueError("recovery_timeout must be >= 0")
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._clock = clock
        self._lock = threading.Lock()
        self._state = BreakerState.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._probe_in_flight = False
        self.opened_count = 0  # times the breaker has tripped (metrics)

    @property
    def state(self) -> BreakerState:
        """Current state (an elapsed OPEN reports HALF_OPEN-pending as OPEN until a probe is admitted)."""
        with self._lock:
            return self._state

    @property
    def consecutive_failures(self) -> int:
        with self._lock:
            return self._failures

    def is_open(self) -> bool:
        """Non-consuming: True while requests would be rejected (open and recovery not yet elapsed)."""
        with self._lock:
            if self._state is BreakerState.OPEN:
                return (self._clock() - self._opened_at) < self.recovery_timeout
            return self._state is BreakerState.HALF_OPEN and self._probe_in_flight

    def allow(self) -> bool:
        """May a request go to the network now? Admits a single probe when recovering."""
        with self._lock:
            if self._state is BreakerState.CLOSED:
                return True
            if self._state is BreakerState.OPEN:
                if (self._clock() - self._opened_at) < self.recovery_timeout:
                    return False
                self._state = BreakerState.HALF_OPEN
                self._probe_in_flight = True
                return True
            # HALF_OPEN: only the one probe is allowed
            if self._probe_in_flight:
                return False
            self._probe_in_flight = True
            return True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._probe_in_flight = False
            self._state = BreakerState.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._probe_in_flight = False
            if self._state is BreakerState.HALF_OPEN:
                self._trip()
                return
            self._failures += 1
            if self._state is BreakerState.CLOSED and self._failures >= self.failure_threshold:
                self._trip()

    def abandon(self) -> None:
        """A probe ended without evidence either way (e.g. client-side error): free the probe slot."""
        with self._lock:
            self._probe_in_flight = False

    def _trip(self) -> None:
        self._state = BreakerState.OPEN
        self._opened_at = self._clock()
        self.opened_count += 1
