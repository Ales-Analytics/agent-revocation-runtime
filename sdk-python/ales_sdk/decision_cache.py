"""In-process ALLOW-only decision cache bound to the revocation epoch."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

CacheKey = tuple[str, "str | None", str, str, str]


def make_key(
    context_id: str, version: str | None, principal_id: str, purpose: str, policy_version: str
) -> CacheKey:
    return (context_id, version, principal_id, purpose, policy_version)


@dataclass
class _Entry:
    revocation_epoch: int
    expires_at: float


class DecisionCache:
    def __init__(self, max_ttl: float = 30.0, clock: Callable[[], float] = time.monotonic) -> None:
        self.max_ttl = max_ttl
        self._clock = clock
        self._entries: dict[CacheKey, _Entry] = {}
        self._latest_epoch = 0
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def latest_epoch(self) -> int:
        return self._latest_epoch

    def put(self, key: CacheKey, decision: str, revocation_epoch: int, ttl: float | None = None) -> bool:
        """Cache an ALLOW. Any other decision is refused (returns False); stale-epoch ALLOWs too."""
        if str(decision) != "ALLOW":
            return False
        with self._lock:
            if revocation_epoch < self._latest_epoch:
                return False
            self._latest_epoch = max(self._latest_epoch, revocation_epoch)
            eff = self.max_ttl if ttl is None else min(ttl, self.max_ttl)
            self._entries[key] = _Entry(revocation_epoch, self._clock() + eff)
            return True

    def get(self, key: CacheKey) -> int | None:
        """Return the epoch the cached ALLOW was issued at, or None on miss/expiry."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= self._clock() or entry.revocation_epoch < self._latest_epoch:
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
            keys = [k for k in self._entries if k[0] == context_id]
            for k in keys:
                del self._entries[k]
            return len(keys)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
