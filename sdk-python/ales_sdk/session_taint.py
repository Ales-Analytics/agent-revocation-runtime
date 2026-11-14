"""Track which context objects each session consumed, so revoked exposure can force a reset."""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .errors import AlesError

log = logging.getLogger("ales.sdk.session_taint")

if TYPE_CHECKING:  # pragma: no cover
    from .client import InvariantClient, ObjectVerdict

ENFORCE_BATCH_SIZE = 1000
REPORT_BATCH_SIZE = 1000  # the server accepts at most 1000 exposures per report


@dataclass(frozen=True)
class Exposure:
    """One context object served to a session, with the authority it was served under."""

    context_id: str
    version: str | None = None
    principal_type: str | None = None
    principal_id: str | None = None
    purpose: str | None = None
    workload: str | None = None


@dataclass
class ReportResult:
    """Outcome of reporting exposures to the server (durable sessions)."""

    reported: int = 0
    #: exposures that carry no principal (and none was supplied): the server cannot store them
    skipped: int = 0
    #: the server's session view after the last report (``generation``, ``needs_reset``, ...), or None
    session: dict[str, Any] | None = None


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
    """In-process exposure tracking, optionally backed by the server's durable store.

    Durable mode is opt-in (``InvariantClient(..., durable_sessions=True)`` or :meth:`bind`): every
    :meth:`record` and :meth:`transfer` then also reports the new exposures to the server
    (``POST /v1/sessions/{id}/exposures``) so they survive a restart and let a revocation flag the session
    (``needs_reset``). Reporting is best-effort and never raises on the hot path: a failed report stays
    pending, is retried on the next record/flush and its error is kept in :attr:`last_report_error`. The
    local record is authoritative for :func:`enforce`; the server copy is what outlives this process.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, dict[Exposure, None]] = {}
        self._lock = threading.Lock()
        self._durable_client: InvariantClient | None = None
        self._pending: dict[str, dict[Exposure, None]] = {}
        self.last_report_error: str | None = None

    @property
    def durable(self) -> bool:
        return self._durable_client is not None

    def bind(self, client: InvariantClient) -> None:
        """Turn on durable mode: report new exposures through ``client`` from now on."""
        self._durable_client = client

    def record(
        self,
        session_id: str,
        context_ids: Iterable[str | tuple[str, str | None]],
        *,
        versions: Mapping[str, str | None] | None = None,
        principal: Mapping[str, str] | None = None,
        purpose: str | None = None,
        workload: str | None = None,
    ) -> None:
        """Record that ``context_ids`` were served to the session.

        Each item is a context id or a ``(context_id, version)`` pair; exposures are kept per exact
        ``(context_id, version)`` so two versions of one object are tracked (and re-authorized) separately.
        ``versions`` supplies a version for bare ids (legacy form). Pass ``principal`` and ``purpose`` so
        that :func:`enforce` can re-authorize the exposure later.
        """
        ptype = pid = None
        if principal is not None:
            pid = principal["id"]
            ptype = principal.get("type", "user")
        vs = versions or {}
        with self._lock:
            bucket = self._sessions.setdefault(session_id, {})
            for item in context_ids:
                if isinstance(item, str):
                    cid, ver = item, vs.get(item)
                else:
                    cid, ver = item[0], item[1]
                exp = Exposure(cid, ver, ptype, pid, purpose, workload)
                bucket[exp] = None
                if self._durable_client is not None:
                    self._pending.setdefault(session_id, {})[exp] = None
        if self._durable_client is not None:
            self.flush(session_id)

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
                if self._durable_client is not None:
                    self._pending.setdefault(to_session, {})[e] = None
        if self._durable_client is not None and src:
            self.flush(to_session)  # the receiver's exposure is recorded server-side too
        return len(src)

    def report(
        self,
        client: InvariantClient,
        session_id: str,
        *,
        principal: Mapping[str, str] | None = None,
        workload: str | None = None,
    ) -> ReportResult:
        """Post every recorded exposure of ``session_id`` to the server (opt-in durable mode, explicit form).

        Exposures are grouped by the principal they were served to. Those recorded without a principal are
        reported under ``principal`` when given, otherwise skipped (the server needs a principal). Raises
        the client's errors (unlike the best-effort background flush)."""
        return self._send(client, session_id, self.exposures_for(session_id), principal, workload)

    def flush(self, session_id: str) -> ReportResult | None:
        """Best-effort send of the pending (not yet reported) exposures of ``session_id``; durable mode only."""
        client = self._durable_client
        if client is None:
            return None
        with self._lock:
            batch = list(self._pending.pop(session_id, ()))
        if not batch:
            return ReportResult()
        try:
            result = self._send(client, session_id, batch, None, None)
        except AlesError as e:
            with self._lock:
                self._pending.setdefault(session_id, {}).update(dict.fromkeys(batch))
            self.last_report_error = f"{type(e).__name__}: {e}"[:300]
            log.warning("durable session report failed (%s); exposures stay pending", self.last_report_error)
            return None
        self.last_report_error = None
        return result

    @staticmethod
    def _send(
        client: InvariantClient,
        session_id: str,
        exposures: Iterable[Exposure],
        principal: Mapping[str, str] | None,
        workload: str | None,
    ) -> ReportResult:
        groups: dict[tuple[str, str, str | None], dict[tuple[str, str | None], None]] = {}
        skipped = 0
        for e in exposures:
            if e.principal_id is not None:
                key = (e.principal_type or "user", e.principal_id, workload or e.workload)
            elif principal is not None:
                key = (principal.get("type", "user"), principal["id"], workload or e.workload)
            else:
                skipped += 1
                continue
            groups.setdefault(key, {})[(e.context_id, e.version)] = None
        out = ReportResult(skipped=skipped)
        for (ptype, pid, wl), pairs in groups.items():
            items = list(pairs)
            for i in range(0, len(items), REPORT_BATCH_SIZE):
                chunk = items[i : i + REPORT_BATCH_SIZE]
                resp = client.report_session_exposures(session_id, {"type": ptype, "id": pid}, chunk, workload=wl)
                out.reported += len(chunk)
                out.session = resp
        return out

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
    groups: dict[tuple[str, str, str], dict[tuple[str, str | None], None]] = {}
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
        groups.setdefault(key, {})[(e.context_id, e.version)] = None

    revoked: dict[tuple[str, str | None], ObjectVerdict] = {}
    checked = 0
    for (ptype, pid, purp), objs in groups.items():
        items = list(objs)
        for i in range(0, len(items), ENFORCE_BATCH_SIZE):
            batch: list[Any] = items[i : i + ENFORCE_BATCH_SIZE]
            result = client.authorize({"type": ptype, "id": pid}, purp, batch, session_id=session_id)
            for cid, ver in batch:
                checked += 1
                v = result.verdict_for(cid, ver)
                if v is None:
                    v = ObjectVerdict(cid, "UNKNOWN", ["OBJECT_UNKNOWN"], ver)
                if v.decision != "ALLOW":
                    revoked.setdefault((cid, ver), v)
    return TaintVerdict(
        session_id=session_id,
        reset_required=bool(revoked or unverifiable),
        revoked=list(revoked.values()),
        unverifiable=unverifiable,
        checked=checked,
    )
