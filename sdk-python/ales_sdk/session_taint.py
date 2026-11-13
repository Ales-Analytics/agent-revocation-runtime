"""Track which context objects each session consumed, so revoked exposure can force a reset."""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from .client import InvariantClient, ObjectVerdict

ENFORCE_BATCH_SIZE = 1000


@dataclass(frozen=True)
class Exposure:
    """One context object served to a session, with the authority it was served under."""

    context_id: str
    version: str | None = None
    principal_type: str | None = None
    principal_id: str | None = None
    purpose: str | None = None


@dataclass
class TaintVerdict:
    session_id: str
    reset_required: bool
    revoked: list[ObjectVerdict] = field(default_factory=list)
    #: context ids that were recorded without principal/purpose and therefore cannot be re-checked
    #: (fail closed: they force ``reset_required``).
    unverifiable: list[str] = field(default_factory=list)
    checked: int = 0


class SessionTaint:
    def __init__(self) -> None:
        self._sessions: dict[str, dict[Exposure, None]] = {}
        self._lock = threading.Lock()

    def record(
        self,
        session_id: str,
        context_ids: Iterable[str],
        *,
        versions: Mapping[str, str | None] | None = None,
        principal: Mapping[str, str] | None = None,
        purpose: str | None = None,
    ) -> None:
        """Record that ``context_ids`` were served to the session.

        Pass ``principal`` and ``purpose`` so that :func:`enforce` can re-authorize the exposure later.
        """
        ptype = pid = None
        if principal is not None:
            pid = principal["id"]
            ptype = principal.get("type", "user")
        vs = versions or {}
        with self._lock:
            bucket = self._sessions.setdefault(session_id, {})
            for cid in context_ids:
                bucket[Exposure(cid, vs.get(cid), ptype, pid, purpose)] = None

    def exposures_for(self, session_id: str) -> list[Exposure]:
        with self._lock:
            return list(self._sessions.get(session_id, ()))

    def contexts_for(self, session_id: str) -> set[str]:
        with self._lock:
            return {e.context_id for e in self._sessions.get(session_id, ())}

    def is_tainted(self, session_id: str, revoked_context_ids: Iterable[str]) -> bool:
        """True if the session consumed any revoked context (caller should reset the session)."""
        return bool(self.contexts_for(session_id) & set(revoked_context_ids))

    def transfer(self, from_session: str, to_session: str) -> int:
        """Copy every exposure of ``from_session`` into ``to_session`` (taint crosses a handoff).

        Exposures keep their principal/purpose so :func:`enforce` can re-authorize them for the
        receiver. The source session's taint is left intact. Returns the number of exposures copied.
        """
        with self._lock:
            src = list(self._sessions.get(from_session, ()))
            bucket = self._sessions.setdefault(to_session, {})
            for e in src:
                bucket[e] = None
        return len(src)

    def clear(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)


def enforce(
    session_id: str,
    client: InvariantClient,
    *,
    principal: Mapping[str, str] | None = None,
    purpose: str | None = None,
) -> TaintVerdict:
    """Re-authorize everything the session has consumed and say whether it must be reset.

    All recorded context ids sharing a ``(principal, purpose)`` are re-checked in one batched
    ``authorize`` call (typically exactly one call per session). Any object that is not an explicit
    ALLOW now -- DENY, UNKNOWN, an offline/stale-snapshot UNKNOWN, a missing verdict -- sets
    ``reset_required``. The check uses the raw server decision and is independent of the fail mode:
    OBSERVE/WARN do not make a revoked exposure acceptable here.

    ``principal``/``purpose`` override whatever was recorded (needed for exposures recorded without
    them; otherwise those are reported as ``unverifiable`` and force a reset).
    """
    from .client import ObjectVerdict

    exposures = client.session_taint.exposures_for(session_id)
    if (principal is None) != (purpose is None):
        raise ValueError("pass both principal and purpose, or neither")
    groups: dict[tuple[str, str, str], dict[str, str | None]] = {}
    unverifiable: list[str] = []
    for e in exposures:
        if principal is not None and purpose is not None:
            key = (principal.get("type", "user"), principal["id"], purpose)
        elif e.principal_id is not None and e.purpose is not None:
            key = (e.principal_type or "user", e.principal_id, e.purpose)
        else:
            if e.context_id not in unverifiable:
                unverifiable.append(e.context_id)
            continue
        groups.setdefault(key, {})[e.context_id] = e.version

    revoked: dict[str, ObjectVerdict] = {}
    checked = 0
    for (ptype, pid, purp), objs in groups.items():
        items = list(objs.items())
        for i in range(0, len(items), ENFORCE_BATCH_SIZE):
            batch: list[Any] = items[i : i + ENFORCE_BATCH_SIZE]
            result = client.authorize({"type": ptype, "id": pid}, purp, batch, session_id=session_id)
            for cid, ver in batch:
                checked += 1
                v = result.verdict_for(cid)
                if v is None:
                    v = ObjectVerdict(cid, "UNKNOWN", ["OBJECT_UNKNOWN"], ver)
                if v.decision != "ALLOW":
                    revoked.setdefault(cid, v)
    return TaintVerdict(
        session_id=session_id,
        reset_required=bool(revoked or unverifiable),
        revoked=list(revoked.values()),
        unverifiable=unverifiable,
        checked=checked,
    )
