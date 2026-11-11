"""Track which context objects each session consumed, so revoked exposure can force a reset."""

from __future__ import annotations

import threading
from collections.abc import Iterable


class SessionTaint:
    def __init__(self) -> None:
        self._sessions: dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def record(self, session_id: str, context_ids: Iterable[str]) -> None:
        with self._lock:
            self._sessions.setdefault(session_id, set()).update(context_ids)

    def contexts_for(self, session_id: str) -> set[str]:
        with self._lock:
            return set(self._sessions.get(session_id, ()))

    def is_tainted(self, session_id: str, revoked_context_ids: Iterable[str]) -> bool:
        """True if the session consumed any revoked context (caller should reset the session)."""
        return bool(self.contexts_for(session_id) & set(revoked_context_ids))

    def clear(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)
