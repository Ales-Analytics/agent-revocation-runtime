"""Optional append-only audit export (``ALES_AUDIT_EXPORT_FILE``), the external anchor for R23.

Every audit record that commits is also written as one JSON line to the file. Records are captured at
flush time and written only after the owning transaction commits (a rolled-back record is never
exported). The file is opened in append mode for each commit batch and fsync-ed. Failures are logged and
counted (``ales_audit_export_failures_total``) but never fail the request: the database ledger stays the
source of truth and the file is a best-effort second copy. It belongs on storage separate from the
database (ideally WORM / append-only) so that an attacker who can rewrite the ledger cannot also rewrite
the export. A record lost to an export failure leaves a gap in ``seq`` that an operator can see.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import UTC, datetime
from typing import Any

from ales_core import AuditLog
from sqlalchemy import event
from sqlalchemy.orm import Session, sessionmaker

from .config import ConfigError
from .metrics import Metrics

log = logging.getLogger("ales.server.audit_export")

_KEY = "ales_audit_export"


def _stamp(dt: datetime) -> str:
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AuditExporter:
    def __init__(self, path: str, metrics: Metrics):
        self.path = path
        self.metrics = metrics
        self._lock = threading.Lock()
        # fail at startup (not on the first audited request) if the location is unusable
        try:
            with open(path, "a", encoding="utf-8"):
                pass
        except OSError as exc:
            raise ConfigError(f"cannot open ALES_AUDIT_EXPORT_FILE {path!r} for append: {exc}") from exc

    def attach(self, factory: sessionmaker) -> None:
        event.listen(factory, "after_flush", self._after_flush)
        event.listen(factory, "after_commit", self._after_commit)
        event.listen(factory, "after_rollback", self._after_rollback)

    @staticmethod
    def _after_flush(session: Session, _ctx: Any) -> None:
        for obj in session.new:
            if isinstance(obj, AuditLog):
                session.info.setdefault(_KEY, []).append(
                    {
                        "tenant_id": obj.tenant_id,
                        "seq": obj.seq,
                        "prev_hash": obj.prev_hash,
                        "hash": obj.hash,
                        "at": _stamp(obj.at),
                        "actor": obj.actor,
                        "action": obj.action,
                        "detail": obj.detail,
                    }
                )

    @staticmethod
    def _after_rollback(session: Session) -> None:
        session.info.pop(_KEY, None)

    def _after_commit(self, session: Session) -> None:
        records = session.info.pop(_KEY, None)
        if not records:
            return
        try:
            blob = "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in records)
            with self._lock, open(self.path, "a", encoding="utf-8") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
        except (OSError, TypeError, ValueError) as exc:
            log.error(
                "audit export failed for %d record(s) (seq %s..): %s", len(records), records[0]["seq"], exc
            )
            self.metrics.inc("audit_export_failure", None, "", len(records))
