"""In-process, thread-safe ALLOW-only decision cache bound to the revocation epoch."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

# (tenant_id, principal_type, principal_id, purpose, context_id, object_version, policy_version)
# Every component that can change the answer to "may this principal use this object for this purpose?"
# is part of the key (SPEC v0.2): two tenants, or a user and a service with the same id, never share.
CacheKey = tuple[str, str, str, str, str, "str | None", str]

_CONTEXT_INDEX = 4
DEFAULT_MAX_ENTRIES = 10_000
DEFAULT_MAX_CLOCK_SKEW = 30.0  # same tolerance as the signed-snapshot lease (snapshot.DEFAULT_MAX_CLOCK_SKEW)


def make_key(
    tenant_id: str,
    principal_type: str,
    principal_id: str,
    purpose: str,
    context_id: str,
    version: str | None,
    policy_version: str,
) -> CacheKey:
    return (tenant_id, principal_type, principal_id, purpose, context_id, version, policy_version)


@dataclass
class _Entry:
    revocation_epoch: int
    expires_at: float
    valid_until: float | None = None  # wall-clock epoch seconds; None = no pending revocation known


class DecisionCache:
    def __init__(
        self,
        max_ttl: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        max_clock_skew: float = DEFAULT_MAX_CLOCK_SKEW,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self.max_entries = max_entries
        self.max_ttl = max_ttl
        self._clock = clock
        # ``valid_until`` is a server wall-clock instant, so it is compared on the wall clock. An entry
        # stops being served ``max_clock_skew`` seconds BEFORE valid_until: a client clock that runs
        # behind the server's must not keep serving an ALLOW past the moment it becomes a DENY.
        self._wall_clock = wall_clock
        self.max_clock_skew = max_clock_skew
        self._entries: dict[CacheKey, _Entry] = {}
        self._latest_epoch = 0
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def maxsize(self) -> int:
        return self.max_entries

    @property
    def latest_epoch(self) -> int:
        with self._lock:
            return self._latest_epoch

    def _past_valid_until(self, valid_until: float | None) -> bool:
        return valid_until is not None and self._wall_clock() + self.max_clock_skew >= valid_until

    def put(
        self,
        key: CacheKey,
        decision: str,
        revocation_epoch: int,
        ttl: float | None = None,
        valid_until: float | None = None,
    ) -> bool:
        """Cache an ALLOW. Any other decision is refused (returns False); stale-epoch ALLOWs too.

        ``valid_until`` (wall-clock epoch seconds, from the server) bounds how long the ALLOW may be
        served; an entry that is already within the skew allowance of it is not stored.
        """
        if str(decision) != "ALLOW" or self._past_valid_until(valid_until):
            return False
        with self._lock:
            if revocation_epoch < self._latest_epoch:
                return False
            self._latest_epoch = max(self._latest_epoch, revocation_epoch)
            eff = self.max_ttl if ttl is None else min(ttl, self.max_ttl)
            if key not in self._entries and len(self._entries) >= self.max_entries:
                self._make_room()
            self._entries[key] = _Entry(revocation_epoch, self._clock() + eff, valid_until)
            return True

    def _make_room(self) -> None:
        """Caller holds the lock. Sweep expired entries (one pass); if still full, evict the entry
        with the earliest ``expires_at``. The min scan is O(n), acceptable at the 10k default."""
        now = self._clock()
        for k in [k for k, e in self._entries.items() if e.expires_at <= now]:
            del self._entries[k]
        if len(self._entries) >= self.max_entries:
            victim = min(self._entries, key=lambda k: self._entries[k].expires_at)
            del self._entries[victim]

    def get(self, key: CacheKey) -> int | None:
        """Return the epoch the cached ALLOW was issued at, or None on miss/expiry."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if (
                entry.expires_at <= self._clock()
                or entry.revocation_epoch < self._latest_epoch
                or self._past_valid_until(entry.valid_until)
            ):
                del self._entries[key]
                return None
            return entry.revocation_epoch

    def invalidate_if_epoch_advanced(self, new_epoch: int) -> int:
        """Wipe entries issued before ``new_epoch``. Returns the number of entries removed."""
        with self._lock:
            self._latest_epoch = max(self._latest_epoch, new_epoch)
            stale = [k for k, e in self._entries.items() if e.revocation_epoch < new_epoch]
            for k in stale:
                del self._entries[k]
            return len(stale)

    def invalidate_context(self, context_id: str) -> int:
        with self._lock:
            keys = [k for k in self._entries if k[_CONTEXT_INDEX] == context_id]
            for k in keys:
                del self._entries[k]
            return len(keys)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
