#!/usr/bin/env python
"""Restore-safety tool for ALES INVARIANT (R22): keep revocations outside the database, re-apply after a restore.

A point-in-time database restore to before a revocation removes its event, tombstones and epoch bump, so
the revoked source is allowed again. This tool keeps an independent record and closes that gap.

Modes (``DATABASE_URL`` or ``--database-url`` selects the database)::

    export  --out revocations.jsonl [--tenant T]     dump events + tombstones + epoch per tenant (JSON lines)
    verify  --file revocations.jsonl [--tenant T]    compare file vs database; exit 1 on any gap
    reapply --file revocations.jsonl [--tenant T]    re-accept every event idempotently; report what was missing

``--file`` accepts this tool's own export OR an ``ALES_AUDIT_EXPORT_FILE`` audit export (its
``revocation.accept`` records carry the event fields; the signature and ``source_event_id`` are not in the
audit detail, so events re-applied from an audit export are unsigned; acceptance does not re-verify
signatures, the original signature check happened at ingress).

Run ``export`` on a schedule (cron) to storage the database operator cannot rewrite, and ``verify`` /
``reapply`` immediately after every restore, BEFORE the control plane serves traffic. ``reapply`` is safe to
run repeatedly: ``RevocationEngine.accept`` is idempotent by ``event_id``.

Exit codes: 0 ok (no gaps / reapply finished), 1 gaps found (verify) or failures (reapply), 2 usage or
input error. A JSON report is written to stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "core") not in sys.path:  # allow running from a checkout without installing ales_core
    sys.path.insert(0, str(_ROOT / "core"))

from ales_core import RevocationEngine, RevocationEvent
from ales_core.db import RevocationEventRow, Tenant, Tombstone
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

REAPPLY_ACTOR = "ales-restore-check"


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _make_session_factory(url: str):
    return sessionmaker(bind=create_engine(url, pool_pre_ping=not url.startswith("sqlite")), expire_on_commit=False)


# ------------------------------------------------------------------------------------------ export
def export_records(session: Session, tenant: str | None = None) -> Iterator[dict[str, Any]]:
    """Yield JSON-serialisable records: one ``epoch`` per tenant, its events and its tombstones."""
    tq = select(Tenant).order_by(Tenant.tenant_id)
    if tenant:
        tq = tq.where(Tenant.tenant_id == tenant)
    for t in session.scalars(tq):
        yield {"type": "epoch", "tenant_id": t.tenant_id, "revocation_epoch": t.revocation_epoch}
        events = session.scalars(
            select(RevocationEventRow)
            .where(RevocationEventRow.tenant_id == t.tenant_id)
            .order_by(RevocationEventRow.resulting_epoch, RevocationEventRow.event_id)
        )
        for ev in events:
            yield {
                "type": "revocation_event",
                "tenant_id": ev.tenant_id,
                "event_id": ev.event_id,
                "source_id": ev.source_id,
                "source_version": ev.source_version,
                "reason": ev.reason,
                "effective_at": _iso(ev.effective_at),
                "source_event_id": ev.source_event_id,
                "actor": ev.actor,
                "affected_scope": ev.affected_scope,
                "signature": ev.signature,
                "issuer_key_id": ev.issuer_key_id,
                "accepted_at": _iso(ev.accepted_at),
                "resulting_epoch": ev.resulting_epoch,
            }
        for tb in session.scalars(select(Tombstone).where(Tombstone.tenant_id == t.tenant_id).order_by(Tombstone.id)):
            yield {
                "type": "tombstone",
                "tenant_id": tb.tenant_id,
                "event_id": tb.event_id,
                "context_id": tb.context_id,
                "object_version": tb.object_version,
                "reason": tb.reason,
                "effective_at": _iso(tb.effective_at),
                "scope_principals": tb.scope_principals,
                "scope_purposes": tb.scope_purposes,
            }


def write_export(session: Session, out: Path, tenant: str | None = None) -> dict[str, int]:
    counts = {"epoch": 0, "revocation_event": 0, "tombstone": 0}
    tmp = out.with_suffix(out.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for rec in export_records(session, tenant):
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
            counts[rec["type"]] += 1
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, out)
    return counts


# ------------------------------------------------------------------------------------------- input
class InputError(ValueError):
    pass


def _event_from_audit(rec: dict[str, Any]) -> dict[str, Any] | None:
    if rec.get("action") != "revocation.accept":
        return None
    d = rec.get("detail") or {}
    scope = d.get("scope")
    return {
        "type": "revocation_event",
        "tenant_id": rec["tenant_id"],
        "event_id": d["event_id"],
        "source_id": d["source_id"],
        "source_version": d.get("source_version"),
        "reason": d["reason"],
        "effective_at": d["effective_at"],
        "actor": d.get("claimed_actor"),
        "affected_scope": {"principals": scope.get("principals"), "purposes": scope.get("purposes")} if scope else None,
        "issuer_key_id": d.get("issuer_key_id"),
        "resulting_epoch": d.get("revocation_epoch"),
    }


def read_records(path: Path, tenant: str | None = None) -> list[dict[str, Any]]:
    """Normalised ``epoch`` / ``revocation_event`` / ``tombstone`` records from either file flavour."""
    out: list[dict[str, Any]] = []
    try:
        fh = path.open(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    with fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if not isinstance(rec, dict):
                    raise TypeError("not an object")
                if rec.get("type") is None and "action" in rec:  # audit export line
                    rec = _event_from_audit(rec)  # type: ignore[assignment]
                    if rec is None:
                        continue
                if rec.get("type") not in ("epoch", "revocation_event", "tombstone"):
                    continue
                if tenant and rec["tenant_id"] != tenant:
                    continue
                if rec["type"] == "revocation_event":
                    for k in ("event_id", "tenant_id", "source_id", "reason", "effective_at"):
                        if not rec.get(k):
                            raise KeyError(k)
                out.append(rec)
            except (ValueError, KeyError, TypeError) as exc:
                raise InputError(f"{path}:{n}: malformed record ({type(exc).__name__}: {exc})") from exc
    return out


def _to_event(rec: dict[str, Any]) -> RevocationEvent:
    return RevocationEvent.model_validate(
        {
            "event_id": rec["event_id"],
            "tenant_id": rec["tenant_id"],
            "source_id": rec["source_id"],
            "source_version": rec.get("source_version"),
            "reason": rec["reason"],
            "effective_at": rec["effective_at"],
            "source_event_id": rec.get("source_event_id"),
            "actor": rec.get("actor"),
            "affected_scope": rec.get("affected_scope"),
            "issuer_key_id": rec.get("issuer_key_id"),
            "signature": rec.get("signature"),
        }
    )


# ---------------------------------------------------------------------------------------- compare
def _db_state(session: Session, records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    tenants = {r["tenant_id"] for r in records}
    event_ids: set[str] = set()
    tomb_keys: set[tuple[str, str]] = set()
    epochs: dict[str, int] = {}
    for t in tenants:
        epochs[t] = session.scalar(select(Tenant.revocation_epoch).where(Tenant.tenant_id == t)) or 0
        event_ids.update(session.scalars(select(RevocationEventRow.event_id).where(RevocationEventRow.tenant_id == t)))
        for tb in session.scalars(select(Tombstone).where(Tombstone.tenant_id == t)):
            tomb_keys.add((tb.event_id, tb.context_id))  # version differs when re-applied to a restored DB
    return {"events": event_ids, "tombstones": tomb_keys, "epochs": epochs}


def find_gaps(session: Session, records: list[dict[str, Any]]) -> dict[str, Any]:
    st = _db_state(session, records)
    missing_events = [r for r in records if r["type"] == "revocation_event" and r["event_id"] not in st["events"]]
    missing_event_ids = {r["event_id"] for r in missing_events}
    missing_tombstones = [
        r
        for r in records
        if r["type"] == "tombstone"
        and r["event_id"] not in missing_event_ids  # an absent event already explains its tombstones
        and (r["event_id"], r["context_id"]) not in st["tombstones"]
    ]
    epoch_behind = [
        {"tenant_id": r["tenant_id"], "file_epoch": r["revocation_epoch"], "db_epoch": st["epochs"].get(r["tenant_id"], 0)}
        for r in records
        if r["type"] == "epoch" and st["epochs"].get(r["tenant_id"], 0) < r["revocation_epoch"]
    ]
    return {
        "missing_events": [
            {k: r.get(k) for k in ("tenant_id", "event_id", "source_id", "source_version", "reason", "effective_at")}
            for r in missing_events
        ],
        "missing_tombstones": [
            {k: r.get(k) for k in ("tenant_id", "event_id", "context_id", "object_version")} for r in missing_tombstones
        ],
        "epoch_behind": epoch_behind,
    }


def _has_gaps(g: dict[str, Any]) -> bool:
    return bool(g["missing_events"] or g["missing_tombstones"] or g["epoch_behind"])


def reapply(session_factory, records: list[dict[str, Any]]) -> dict[str, Any]:
    with session_factory() as s:
        present = _db_state(s, records)["events"]
    events = [r for r in records if r["type"] == "revocation_event"]
    reapplied: list[str] = []
    failed: list[dict[str, str]] = []
    engine = RevocationEngine()
    for rec in events:  # file order == per-tenant epoch order for an export, seq order for an audit export
        if rec["event_id"] in present:
            continue
        try:
            with session_factory() as s:
                engine.accept(s, _to_event(rec), actor=REAPPLY_ACTOR)
            reapplied.append(rec["event_id"])
        except Exception as exc:  # noqa: BLE001 - report every failure, keep going
            failed.append({"event_id": rec["event_id"], "error": f"{type(exc).__name__}: {exc}"[:300]})
    with session_factory() as s:
        remaining = find_gaps(s, records)
    return {
        "events_in_file": len(events),
        "already_present": len(events) - len(reapplied) - len(failed),
        "reapplied": reapplied,
        "failed": failed,
        "remaining_gaps": remaining,
    }


# ------------------------------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--database-url", default=None, help="SQLAlchemy URL (default: $DATABASE_URL)")
    ap.add_argument("--tenant", default=None, help="restrict to one tenant")
    sub = ap.add_subparsers(dest="mode", required=True)
    e = sub.add_parser("export", help="dump revocation events, tombstones and epochs as JSON lines")
    e.add_argument("--out", required=True, type=Path)
    for name, help_ in (("verify", "compare file vs database; exit 1 on gaps"), ("reapply", "re-accept missing events")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("--file", required=True, type=Path)
    args = ap.parse_args(argv)

    url = args.database_url or os.environ.get("DATABASE_URL")
    if not url:
        print("error: set DATABASE_URL or pass --database-url", file=sys.stderr)
        return 2
    factory = _make_session_factory(url)
    try:
        if args.mode == "export":
            with factory() as s:
                counts = write_export(s, args.out, args.tenant)
            print(json.dumps({"mode": "export", "out": str(args.out), "records": counts}))
            return 0
        records = read_records(args.file, args.tenant)
        if args.mode == "verify":
            with factory() as s:
                gaps = find_gaps(s, records)
            ok = not _has_gaps(gaps)
            print(json.dumps({"mode": "verify", "ok": ok, **gaps}, indent=2))
            return 0 if ok else 1
        report = reapply(factory, records)
        ok = not report["failed"] and not _has_gaps(report["remaining_gaps"])
        print(json.dumps({"mode": "reapply", "ok": ok, **report}, indent=2))
        return 0 if ok else 1
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
