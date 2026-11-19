"""Durable session exposures: which sessions were served which context objects, with bounded retention.

The SDK's in-process :class:`SessionTaint` forgets everything when the process restarts. This module is the
server-side counterpart: SDKs (or hosts) *report* exposures, the revocation engine *flags* the sessions whose
exposure a revocation reaches (``needs_reset``), and the impact preview *counts* them before a revocation.

What this is and is not:

* Reporting is voluntary. ALES learns only what a host tells it; a session that was never reported is
  invisible (the impact preview says so instead of claiming zero).
* ``needs_reset`` is a flag, not an action. What a reset means for an agent runtime (drop the conversation,
  truncate memory, restart the run) is host-defined. A reset bumps the session ``generation``; exposures
  recorded under an older generation stop counting. Information already disclosed to a model or a human cannot
  be recalled by any of this.
* Retention is bounded: every row carries ``expires_at`` (``now + retention`` at the last report) and
  :func:`purge_expired` deletes lapsed rows. An expired session is forgotten, so a revocation that lands after
  expiry flags nothing.

Nothing here commits; callers own the transaction. Writers take :func:`ales_core.db.lock_tenant`, the same
per-tenant serialisation point as the audit ledger.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import audit
from .db import SessionExposureRow, SessionStateRow, lock_tenant, utcnow
from .exceptions import AlesError
from .tombstones import utc

DEFAULT_RETENTION = timedelta(days=7)
MAX_PAIRS_PER_CALL = 1000
IN_CHUNK = 400
MAX_FLAG_AUDIT_IDS = 20

Pair = tuple[str, str | None]


class SessionError(AlesError):
    """Invalid exposure report or unknown session."""


@dataclass(frozen=True)
class SessionView:
    session_id: str
    generation: int
    needs_reset: bool
    flag_reason: str | None
    flagged_at: datetime | None
    last_reset_at: datetime | None
    expires_at: datetime
    exposure_count: int


def _state(session: Session, tenant: str, session_id: str) -> SessionStateRow | None:
    return session.get(SessionStateRow, (tenant, session_id))


def _chunks(items: Sequence[str], n: int = IN_CHUNK) -> Iterable[Sequence[str]]:
    for i in range(0, len(items), n):
        yield items[i : i + n]


def record_exposure(
    session: Session,
    tenant: str,
    session_id: str,
    principal: dict[str, str] | object,
    workload: str | None,
    pairs: Iterable[Pair],
    now: datetime | None = None,
    *,
    retention: timedelta = DEFAULT_RETENTION,
) -> int:
    """Upsert exposures of ``session_id`` to ``pairs`` ``(context_id, version-or-None)``; return how many
    distinct pairs were recorded. ``principal`` is a ``{"type", "id"}`` mapping or an object with ``type`` /
    ``id``. A ``None`` version is stored as ``""`` and matches any version of that object. Creates the session
    state row on first sight; refreshes retention on every call."""
    if not session_id:
        raise SessionError("session_id required")
    if isinstance(principal, dict):
        principal_type, pid = str(principal.get("type", "user")), str(principal["id"])
    else:
        principal_type, pid = str(getattr(principal, "type", "user")), str(principal.id)  # type: ignore[attr-defined]
    if not pid:
        raise SessionError("principal id required")
    uniq: dict[tuple[str, str], None] = {}
    for context_id, version in pairs:
        if not context_id:
            raise SessionError("context_id required")
        uniq[(context_id, version or "")] = None
    if len(uniq) > MAX_PAIRS_PER_CALL:
        raise SessionError(f"at most {MAX_PAIRS_PER_CALL} exposures per report")
    when = utc(now) if now else utcnow()
    expires = when + retention
    lock_tenant(session, tenant)
    st = _state(session, tenant, session_id)
    if st is None:
        st = SessionStateRow(
            tenant_id=tenant,
            session_id=session_id,
            generation=0,
            needs_reset=False,
            created_at=when,
            expires_at=expires,
        )
        session.add(st)
        session.flush()
    else:
        st.expires_at = expires
    existing = {
        (r.context_id, r.object_version): r
        for r in session.scalars(
            select(SessionExposureRow).where(
                SessionExposureRow.tenant_id == tenant,
                SessionExposureRow.session_id == session_id,
                SessionExposureRow.generation == st.generation,
                SessionExposureRow.principal_id == pid,
            )
        )
    }
    for context_id, version in uniq:
        row = existing.get((context_id, version))
        if row is None:
            session.add(
                SessionExposureRow(
                    tenant_id=tenant,
                    session_id=session_id,
                    context_id=context_id,
                    object_version=version,
                    generation=st.generation,
                    principal_type=principal_type,
                    principal_id=pid,
                    workload=workload,
                    first_seen_at=when,
                    last_seen_at=when,
                    expires_at=expires,
                )
            )
        else:
            row.last_seen_at = when
            row.expires_at = expires
            if workload is not None:
                row.workload = workload
    session.flush()
    return len(uniq)


def _live_exposures(
    session: Session, tenant: str, nodes: Iterable[Pair], now: datetime
) -> list[tuple[SessionExposureRow, SessionStateRow | None]]:
    """Unexpired, current-generation exposure rows matching any of ``nodes`` (an exposure with version
    ``""`` matches every version of its context id)."""
    wanted: dict[str, set[str]] = {}
    for context_id, version in nodes:
        wanted.setdefault(context_id, set()).add(version or "")
    result: list[tuple[SessionExposureRow, SessionStateRow | None]] = []
    when = utc(now)
    for chunk in _chunks(sorted(wanted)):
        rows = [
            r
            for r in session.scalars(
                select(SessionExposureRow).where(
                    SessionExposureRow.tenant_id == tenant,
                    SessionExposureRow.context_id.in_(list(chunk)),
                    SessionExposureRow.expires_at > when,
                )
            )
            if r.object_version == ""
            or "" in wanted[r.context_id]
            or r.object_version in wanted[r.context_id]
        ]
        sids = sorted({r.session_id for r in rows})
        states: dict[str, SessionStateRow] = {}
        for sc in _chunks(sids):
            for st in session.scalars(
                select(SessionStateRow).where(
                    SessionStateRow.tenant_id == tenant, SessionStateRow.session_id.in_(list(sc))
                )
            ):
                states[st.session_id] = st
        for r in rows:
            current = states.get(r.session_id)
            if r.generation == (current.generation if current is not None else 0):
                result.append((r, current))
    return result


def exposed_sessions(
    session: Session,
    tenant: str,
    cids: Iterable[str | Pair],
    now: datetime | None = None,
) -> list[str]:
    """Sorted ids of sessions (current generation, unexpired) exposed to any of ``cids``. Items are context
    ids (any version) or ``(context_id, version)`` pairs."""
    nodes: list[Pair] = [(c, None) if isinstance(c, str) else (c[0], c[1]) for c in cids]
    when = utc(now) if now else utcnow()
    return sorted({row.session_id for row, _ in _live_exposures(session, tenant, nodes, when)})


def has_any_exposures(session: Session, tenant: str, now: datetime | None = None) -> bool:
    """True when the tenant has at least one live reported exposure (so "no sessions" can be asserted)."""
    when = utc(now) if now else utcnow()
    n = session.scalar(
        select(func.count())
        .select_from(SessionExposureRow)
        .where(SessionExposureRow.tenant_id == tenant, SessionExposureRow.expires_at > when)
    )
    return bool(n)


def flag_for_revocation(
    session: Session,
    tenant: str,
    nodes: Iterable[Pair],
    now: datetime,
    *,
    event_id: str,
    actor: str,
    principals: Sequence[str] | None = None,
) -> list[str]:
    """Mark every session exposed to any of ``nodes`` as ``needs_reset``; return the flagged ids.

    ``principals`` narrows the flag for a *scoped* revocation to sessions that exposed the object to one of
    those principals (bare ids; a conservative text match, group entries are not expanded). Audits one
    ``session.flag`` record when at least one session was flagged."""
    live = _live_exposures(session, tenant, nodes, now)
    if principals:
        allowed = set(principals)
        live = [(r, st) for r, st in live if r.principal_id in allowed]
    ids = sorted({r.session_id for r, _ in live})
    if not ids:
        return []
    when = utc(now)
    reason = f"revocation:{event_id}"[:255]
    for sid in ids:
        st = _state(session, tenant, sid)
        if st is None:  # defensive: an exposure without a state row
            continue
        st.needs_reset = True
        st.flagged_at = when
        st.flag_reason = reason
    session.flush()
    audit.append(
        session,
        tenant,
        actor,
        "session.flag",
        {"event_id": event_id, "flagged": len(ids), "session_ids": ids[:MAX_FLAG_AUDIT_IDS]},
        at=when,
    )
    return ids


def get_session_view(
    session: Session, tenant: str, session_id: str, now: datetime | None = None
) -> SessionView | None:
    st = _state(session, tenant, session_id)
    when = utc(now) if now else utcnow()
    if st is None or utc(st.expires_at) <= when:
        return None
    n = session.scalar(
        select(func.count())
        .select_from(SessionExposureRow)
        .where(
            SessionExposureRow.tenant_id == tenant,
            SessionExposureRow.session_id == session_id,
            SessionExposureRow.generation == st.generation,
            SessionExposureRow.expires_at > when,
        )
    )
    return SessionView(
        session_id=session_id,
        generation=st.generation,
        needs_reset=st.needs_reset,
        flag_reason=st.flag_reason,
        flagged_at=utc(st.flagged_at) if st.flagged_at else None,
        last_reset_at=utc(st.last_reset_at) if st.last_reset_at else None,
        expires_at=utc(st.expires_at),
        exposure_count=int(n or 0),
    )


def reset_session(
    session: Session, tenant: str, session_id: str, actor: str, now: datetime | None = None
) -> SessionView:
    """Bump the session generation and clear ``needs_reset`` (audited ``session.reset``). The host performs
    the actual reset; this records that it did. Raises :class:`SessionError` for an unknown session."""
    when = utc(now) if now else utcnow()
    lock_tenant(session, tenant)
    st = _state(session, tenant, session_id)
    if st is None or utc(st.expires_at) <= when:
        raise SessionError(f"unknown session {session_id!r}")
    before = st.generation
    was_flagged = st.needs_reset
    had_exposures = bool(
        session.scalar(
            select(func.count())
            .select_from(SessionExposureRow)
            .where(
                SessionExposureRow.tenant_id == tenant,
                SessionExposureRow.session_id == session_id,
                SessionExposureRow.generation == before,
            )
        )
    )
    st.generation = before + 1
    st.needs_reset = False
    st.flag_reason = None
    st.flagged_at = None
    st.last_reset_at = when
    session.flush()
    audit.append(
        session,
        tenant,
        actor,
        "session.reset",
        {
            "session_id": session_id[:255],
            "generation_from": before,
            "generation_to": st.generation,
            "had_exposures": had_exposures,
            "was_flagged": was_flagged,
        },
        at=when,
    )
    view = get_session_view(session, tenant, session_id, when)
    assert view is not None
    return view


def purge_expired(session: Session, now: datetime | None = None) -> int:
    """Delete lapsed exposure and state rows of every tenant; return the number of rows removed. Does not
    commit. Exposure rows left behind by a reset (older generation) go when they lapse like any other."""
    when = utc(now) if now else utcnow()
    n = 0
    for model in (SessionExposureRow, SessionStateRow):
        result = session.execute(delete(model).where(model.expires_at <= when))
        n += int(getattr(result, "rowcount", 0) or 0)
    return n
