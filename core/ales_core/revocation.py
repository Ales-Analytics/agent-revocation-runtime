"""Revocation engine: durable tombstoning of a source and all descendants in one transaction.

Acceptance is atomic: event row, tombstones, epoch bump, outbox rows and audit record commit
together or not at all. No adapter side effect happens here.

Semantics:

* ``effective_at`` in the future: the event is durable and the epoch advances now, but the
  resolver only denies once ``now >= effective_at``; purge is scheduled for ``effective_at``.
* ``affected_scope``: tombstones carry the scope; the resolver denies only matching
  principals/purposes. Scoped events schedule no purge (purge is global).
* Roots are the registered versions matching ``source_id``/``source_version`` at acceptance
  (``source_version`` null = every version registered *at that moment*). If none match
  (unknown source) the event is kept as a pending tombstone and applied when a matching
  version is registered later (null version = every version registered later).
* Idempotent by ``event_id``; duplicate/reordered deliveries converge on the same state.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import audit
from .db import ContextObject, RevocationEventRow, Tenant, Tombstone
from .graph import GraphStore, Node
from .models import RevocationEvent
from .tombstones import enqueue_outbox, mark_flag, normalize_scope, utc


class RevocationEngine:
    def accept(
        self,
        session: Session,
        event: RevocationEvent,
        *,
        now: datetime | None = None,
        actor: str | None = None,
    ) -> int:
        """Persist and apply the event; return the tenant revocation epoch it produced.

        Idempotent on event_id (returns the originally recorded epoch). Commits the session.
        ``now`` is the acceptance time (defaults to wall clock); ``actor`` is the
        *authenticated* caller for the audit ledger (the event's own ``actor`` field is
        caller-claimed and is recorded only as ``claimed_actor``).
        """
        existing = session.get(RevocationEventRow, event.event_id)
        if existing is not None:
            return existing.resulting_epoch
        try:
            epoch = self._apply(session, event, utc(now) if now else datetime.now(UTC), actor)
            session.commit()
        except IntegrityError:
            session.rollback()
            # A concurrent acceptance of the very same event won the race: idempotent success.
            existing = session.get(RevocationEventRow, event.event_id)
            if existing is not None:
                return existing.resulting_epoch
            raise
        except Exception:
            session.rollback()
            raise
        return epoch

    def _apply(self, session: Session, event: RevocationEvent, now: datetime, actor: str | None) -> int:
        graph = GraphStore(session)
        graph.ensure_tenant(event.tenant_id)
        reason = event.reason.value
        effective_at = utc(event.effective_at)
        principals, purposes = normalize_scope(event.affected_scope)
        scoped = principals is not None or purposes is not None
        effective_now = effective_at <= now

        roots = graph.get_versions(event.tenant_id, event.source_id)
        if event.source_version is not None:
            roots = [r for r in roots if r.object_version == event.source_version]
        root_nodes: list[Node] = [(r.context_id, r.object_version) for r in roots]

        affected: dict[Node, None] = dict.fromkeys(root_nodes)
        if not scoped:
            for r in roots:
                for n in graph.get_descendants(event.tenant_id, r.context_id, r.object_version):
                    affected[n] = None
        rows = graph.load_objects(event.tenant_id, list(affected))

        # Tombstones live on the roots only: the resolver walks ancestors, so every present and
        # future descendant is covered. With no root the tombstone is pending (see module doc).
        versions: list[str | None] = [v for _, v in root_nodes] or [event.source_version]
        for v in versions:
            session.add(
                Tombstone(
                    tenant_id=event.tenant_id,
                    event_id=event.event_id,
                    context_id=event.source_id,
                    object_version=v,
                    reason=reason,
                    effective_at=effective_at,
                    scope_principals=principals,
                    scope_purposes=purposes,
                )
            )

        if not scoped:
            for node in affected:
                row: ContextObject | None = rows.get(node)
                if row is None:
                    continue
                if effective_now:
                    mark_flag(row, reason)
                enqueue_outbox(session, row, reason, event.event_id, effective_at)

        session.execute(
            update(Tenant)
            .where(Tenant.tenant_id == event.tenant_id)
            .values(revocation_epoch=Tenant.revocation_epoch + 1)
        )
        epoch = session.execute(
            select(Tenant.revocation_epoch).where(Tenant.tenant_id == event.tenant_id)
        ).scalar_one()

        session.add(
            RevocationEventRow(
                event_id=event.event_id,
                tenant_id=event.tenant_id,
                source_id=event.source_id,
                source_version=event.source_version,
                reason=reason,
                effective_at=effective_at,
                source_event_id=event.source_event_id,
                actor=event.actor,
                affected_scope=event.affected_scope.model_dump() if event.affected_scope else None,
                signature=event.signature,
                issuer_key_id=event.issuer_key_id,
                resulting_epoch=epoch,
            )
        )
        session.flush()

        audit.append(
            session,
            event.tenant_id,
            actor or "unauthenticated",
            "revocation.accept",
            {
                "event_id": event.event_id,
                "source_id": event.source_id,
                "source_version": event.source_version,
                "reason": reason,
                "effective_at": effective_at.isoformat().replace("+00:00", "Z"),
                "claimed_actor": event.actor[:255] if event.actor else None,
                "scope": {"principals": principals, "purposes": purposes} if scoped else None,
                "roots": len(root_nodes),
                "affected_objects": len(affected),
                "pending_unknown_source": not root_nodes,
                "issuer_key_id": event.issuer_key_id[:255] if event.issuer_key_id else None,
                "revocation_epoch": epoch,
            },
            at=now,
        )
        return epoch
