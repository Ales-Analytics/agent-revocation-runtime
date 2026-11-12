"""Invalidation outbox dispatcher: leased, at-least-once, idempotent purge with backoff + dead letter.

Safety argument: use-time decisions depend only on tombstones, never on purge state. Purge is
therefore pure cleanup: a crash, a failing handler, a stuck lease or a dead-lettered row can
delay or prevent cleanup, but can never re-expose data.

Row lifecycle: ``pending -> leased -> done`` or, on handler failure, ``leased -> pending``
(retry at ``available_at = now + backoff[attempt-1]``) until the attempt budget is spent, then
``dead``. A lease that expires without completion (crashed worker) is reclaimable.

Single-flight is a compare-and-swap: a row is leased by an UPDATE whose WHERE clause restates
the "leasable" condition, and completion/failure UPDATEs are conditional on the lease token.
Two dispatchers can never both win a lease, and a worker whose lease was reclaimed cannot
overwrite the new owner's outcome. Handlers must be idempotent (redelivery is expected).

``handlers`` maps ``store_kind`` (the object's kind: chunk, embedding, cache, memory, ...; the
key ``"*"`` is a catch-all) to ``callable(row) -> None``. The row is a detached, read-only
snapshot of the outbox row. Rows whose kind has no handler are left untouched.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Result, and_, func, or_, select, update
from sqlalchemy.orm import Session


def _rc(result: Result[Any]) -> int:
    """Rows affected by an UPDATE; typed accessor for CursorResult.rowcount."""
    return int(getattr(result, "rowcount", 0) or 0)

from .db import InvalidationOutbox

#: Retry delays after the 1st..5th failure; the 6th failure dead-letters the row.
BACKOFF_SECONDS: tuple[int, ...] = (1, 5, 30, 120, 600)
MAX_ATTEMPTS = len(BACKOFF_SECONDS) + 1
DEFAULT_LEASE_SECONDS = 60
MAX_ERROR_CHARS = 1000

Handler = Callable[[InvalidationOutbox], None]


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


@dataclass(frozen=True)
class RunResult:
    leased: int = 0
    done: int = 0
    failed: int = 0  # handler raised; will retry
    dead: int = 0  # moved to dead-letter this run
    lost_lease: int = 0  # finished work but another dispatcher owned the row by then


class OutboxDispatcher:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        handlers: Mapping[str, Handler],
        *,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        max_attempts: int = MAX_ATTEMPTS,
    ):
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self.session_factory = session_factory
        self.handlers = dict(handlers)
        self.lease_seconds = lease_seconds
        self.max_attempts = max_attempts

    # ------------------------------------------------------------------ leasing
    def _leasable(self, now: datetime):
        return or_(
            and_(InvalidationOutbox.state == "pending", InvalidationOutbox.available_at <= now),
            and_(InvalidationOutbox.state == "leased", InvalidationOutbox.lease_expires_at <= now),
        )

    def _kind_filter(self):
        if "*" in self.handlers:
            return None
        return InvalidationOutbox.store_kind.in_(list(self.handlers))

    def _lease(self, now: datetime, batch_size: int, token: str) -> tuple[list[int], int]:
        """Lease up to ``batch_size`` due rows; return (leased ids, dead-lettered count)."""
        leased: list[int] = []
        dead = 0
        with self.session_factory() as s:
            cond = [self._leasable(now)]
            kf = self._kind_filter()
            if kf is not None:
                cond.append(kf)
            ids = list(
                s.scalars(
                    select(InvalidationOutbox.id)
                    .where(*cond)
                    .order_by(InvalidationOutbox.available_at, InvalidationOutbox.id)
                    .limit(batch_size)
                )
            )
            for rid in ids:
                # A reclaimed (expired-lease) row that already burned its attempt budget is dead,
                # not retried forever behind a worker that keeps crashing on it.
                exhausted = _rc(s.execute(
                    update(InvalidationOutbox)
                    .where(
                        InvalidationOutbox.id == rid,
                        self._leasable(now),
                        InvalidationOutbox.attempts >= self.max_attempts,
                    )
                    .values(
                        state="dead",
                        lease_token=None,
                        lease_expires_at=None,
                        last_error="attempt budget exhausted (lease expired without completion)",
                    )
                ))
                if exhausted:
                    dead += 1
                    continue
                won = _rc(s.execute(
                    update(InvalidationOutbox)
                    .where(InvalidationOutbox.id == rid, self._leasable(now))
                    .values(
                        state="leased",
                        lease_token=token,
                        lease_expires_at=now + timedelta(seconds=self.lease_seconds),
                        attempts=InvalidationOutbox.attempts + 1,
                    )
                ))
                if won:
                    leased.append(rid)
            s.commit()
        return leased, dead

    # ---------------------------------------------------------------- run
    def run_once(self, now: datetime | None = None, batch_size: int = 100) -> RunResult:
        """Lease due rows, invoke handlers, record outcomes. ``now`` drives leases and backoff."""
        now = _utc(now) if now else datetime.now(UTC)
        token = uuid.uuid4().hex
        leased_ids, dead = self._lease(now, batch_size, token)
        if not leased_ids:
            return RunResult(dead=dead)

        with self.session_factory() as s:
            rows = list(
                s.scalars(
                    select(InvalidationOutbox)
                    .where(InvalidationOutbox.id.in_(leased_ids), InvalidationOutbox.lease_token == token)
                    .order_by(InvalidationOutbox.id)
                )
            )
            s.expunge_all()  # detached snapshots; the read transaction ends when the session closes

        done = failed = lost = 0
        for row in rows:
            handler = self.handlers.get(row.store_kind) or self.handlers.get("*")
            err: str | None = None
            try:
                if handler is None:  # cannot happen via _kind_filter; defensive
                    raise LookupError(f"no handler for store_kind {row.store_kind!r}")
                handler(row)
            except Exception as exc:  # noqa: BLE001 - handler failure must never abort the batch
                err = f"{type(exc).__name__}: {exc}"[:MAX_ERROR_CHARS]
            outcome = self._finish(row, token, now, err)
            if outcome == "done":
                done += 1
            elif outcome == "retry":
                failed += 1
            elif outcome == "dead":
                failed += 1
                dead += 1
            else:
                lost += 1
        return RunResult(leased=len(rows), done=done, failed=failed, dead=dead, lost_lease=lost)

    def _finish(self, row: InvalidationOutbox, token: str, now: datetime, err: str | None) -> str:
        guard = (
            InvalidationOutbox.id == row.id,
            InvalidationOutbox.lease_token == token,
            InvalidationOutbox.state == "leased",
        )
        with self.session_factory() as s:
            if err is None:
                n = _rc(s.execute(
                    update(InvalidationOutbox)
                    .where(*guard)
                    .values(
                        state="done",
                        dispatched=True,
                        lease_token=None,
                        lease_expires_at=None,
                        last_error=None,
                    )
                ))
                outcome = "done"
            elif row.attempts >= self.max_attempts:
                n = _rc(s.execute(
                    update(InvalidationOutbox)
                    .where(*guard)
                    .values(state="dead", lease_token=None, lease_expires_at=None, last_error=err)
                ))
                outcome = "dead"
            else:
                delay = BACKOFF_SECONDS[min(row.attempts, len(BACKOFF_SECONDS)) - 1]
                n = _rc(s.execute(
                    update(InvalidationOutbox)
                    .where(*guard)
                    .values(
                        state="pending",
                        lease_token=None,
                        lease_expires_at=None,
                        last_error=err,
                        available_at=now + timedelta(seconds=delay),
                    )
                ))
                outcome = "retry"
            s.commit()
        return outcome if n else "lost"


def outbox_stats(session: Session, tenant_id: str | None = None) -> dict[str, Any]:
    """Connector-health view: counts per (store_kind, state) and dead-letter total."""
    stmt = select(InvalidationOutbox.store_kind, InvalidationOutbox.state, func.count())
    if tenant_id is not None:
        stmt = stmt.where(InvalidationOutbox.tenant_id == tenant_id)
    by_kind: dict[str, dict[str, int]] = {}
    totals: dict[str, int] = {"pending": 0, "leased": 0, "done": 0, "dead": 0}
    for kind, state, n in session.execute(stmt.group_by(InvalidationOutbox.store_kind, InvalidationOutbox.state)):
        by_kind.setdefault(kind, {})[state] = n
        totals[state] = totals.get(state, 0) + n
    return {"totals": totals, "by_store_kind": by_kind, "dead": totals.get("dead", 0)}
