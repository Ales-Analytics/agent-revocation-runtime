"""Revocation engine: durable tombstoning of a source and all descendants in one transaction."""

from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .db import ContextObject, InvalidationOutbox, RevocationEventRow, Tenant
from .graph import GraphStore, Node
from .models import RevocationEvent


class RevocationEngine:
    def accept(self, session: Session, event: RevocationEvent) -> int:
        """Persist and apply the event; return the tenant revocation epoch it produced.

        Idempotent on event_id (returns the originally recorded epoch). Commits the session:
        the event row, tombstones, epoch bump and outbox rows land atomically, and no
        adapter side effect happens here (the outbox is dispatched asynchronously later).
        """
        existing = session.get(RevocationEventRow, event.event_id)
        if existing is not None:
            return existing.resulting_epoch
        try:
            epoch = self._apply(session, event)
            session.commit()
        except Exception:
            session.rollback()
            raise
        return epoch

    def _apply(self, session: Session, event: RevocationEvent) -> int:
        graph = GraphStore(session)
        graph.ensure_tenant(event.tenant_id)
        reason = event.reason.value

        roots = graph.get_versions(event.tenant_id, event.source_id)
        if event.source_version is not None:
            roots = [r for r in roots if r.object_version == event.source_version]
        root_nodes: list[Node] = [(r.context_id, r.object_version) for r in roots]

        affected: dict[Node, None] = dict.fromkeys(root_nodes)
        for r in roots:
            for n in graph.get_descendants(event.tenant_id, r.context_id, r.object_version):
                affected[n] = None
        rows = graph.load_objects(event.tenant_id, list(affected))

        for node in affected:
            row: ContextObject | None = rows.get(node)
            if row is None:
                continue
            if not row.tombstoned:
                row.tombstoned = True
                row.tombstone_reason = reason
            session.add(
                InvalidationOutbox(
                    tenant_id=event.tenant_id,
                    context_id=node[0],
                    version=node[1],
                    reason=reason,
                    dispatched=False,
                )
            )

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
                effective_at=event.effective_at,
                source_event_id=event.source_event_id,
                actor=event.actor,
                affected_scope=event.affected_scope.model_dump() if event.affected_scope else None,
                signature=event.signature,
                resulting_epoch=epoch,
            )
        )
        session.flush()
        return epoch
