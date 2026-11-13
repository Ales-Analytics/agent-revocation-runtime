"""Background outbox dispatcher thread."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping

from ales_core import InvalidationOutbox, OutboxDispatcher
from sqlalchemy import and_
from sqlalchemy.orm import Session

log = logging.getLogger("ales.server.outbox")

Handler = Callable[[InvalidationOutbox], None]


def log_only_handler(row: InvalidationOutbox) -> None:
    """DEFAULT HANDLER, LOG-ONLY: records that a purge is due but purges nothing.

    Deployments must register real per-store purge handlers (``create_app(outbox_handlers=...)``).
    Until then rows are marked ``done`` although no store was purged. Safety is unaffected (use-time
    decisions depend only on tombstones), but connector health will not reflect real purge state.
    Identifiers only; never document content.
    """
    log.info(
        "outbox purge due (LOG-ONLY handler, nothing purged): tenant=%s context=%s version=%s kind=%s reason=%s",
        row.tenant_id,
        row.context_id,
        row.version,
        row.store_kind,
        row.reason,
    )


log_only_handler.log_only = True  # type: ignore[attr-defined]


def handlers_mode(handlers: Mapping[str, Handler]) -> str:
    """``log_only`` (default), ``purge:<target,...>`` for real purge handlers, else ``custom``.

    Purge handlers (``ales_adapters.PurgeRegistry``) advertise their target names through a
    ``purge_targets`` attribute; the names are reported so operators can see which stores are wired.
    """
    if not handlers or all(getattr(h, "log_only", False) for h in handlers.values()):
        return "log_only"
    if all(hasattr(h, "purge_targets") for h in handlers.values()):
        names = sorted({n for h in handlers.values() for n in h.purge_targets})  # type: ignore[attr-defined]
        return "purge:" + ",".join(names)
    return "custom"


class TenantOutboxDispatcher(OutboxDispatcher):
    """Dispatcher that only ever leases (and therefore processes and counts) one tenant's rows.

    Used by ``POST /v1/outbox/run`` so an admin of tenant A cannot cause work on, or learn counts about,
    tenant B's rows. Every lease statement (candidate select, budget-exhausted update, lease CAS) restates
    ``_leasable``, so narrowing it narrows all of them. Depends on that private hook of the core
    dispatcher; ``test_outbox_ops`` pins the behaviour.
    """

    def __init__(self, tenant_id: str, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.tenant_id = tenant_id

    def _leasable(self, now):  # type: ignore[no-untyped-def]
        return and_(super()._leasable(now), InvalidationOutbox.tenant_id == self.tenant_id)


class OutboxWorker:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        handlers: Mapping[str, Handler],
        interval: float,
    ) -> None:
        self.interval = interval
        self.handlers = dict(handlers)
        self.dispatcher = OutboxDispatcher(session_factory, self.handlers)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.runs = 0
        self.last_error: str | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="ales-outbox-worker", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.dispatcher.run_once()
                self.last_error = None
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"[:300]
                log.exception("outbox worker tick failed")
            self.runs += 1
            self._stop.wait(self.interval)

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        t = self._thread
        if t is not None:
            t.join(timeout)
            if t.is_alive():  # pragma: no cover - a handler is stuck; daemon thread dies with the process
                log.warning("outbox worker did not stop within %.0fs", timeout)
        self._thread = None
