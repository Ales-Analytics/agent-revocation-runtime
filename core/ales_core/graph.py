"""Lineage graph store. Every query is partitioned by tenant_id."""

from __future__ import annotations

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from .db import ContextObject, DerivationEdge, Tenant
from .exceptions import DuplicateContext, InvalidEnvelope, LineageIncomplete
from .models import ContextEnvelope, Kind
from .propagation import check_not_wider, effective_authority

Node = tuple[str, str]  # (context_id, object_version)


def _row_from_envelope(env: ContextEnvelope) -> ContextObject:
    return ContextObject(
        context_id=env.context_id,
        object_version=env.object_version,
        tenant_id=env.tenant_id,
        object_id=env.object_id,
        kind=env.kind.value,
        content_digest=env.content_digest,
        classification=env.classification.value,
        trust_state=env.trust_state.value,
        principal_scope=list(env.principal_scope),
        purpose_scope=list(env.purpose_scope),
        valid_from=env.valid_from,
        expires_at=env.expires_at,
        source_system=env.source_system,
        source_acl_ref=env.source_acl_ref,
        policy_version=env.policy_version,
        signature=env.signature,
        tombstoned=False,
        tombstone_reason=None,
    )


class GraphStore:
    def __init__(self, session: Session):
        self.session = session

    # ---------------------------------------------------------------- tenants
    def ensure_tenant(self, tenant_id: str) -> Tenant:
        t = self.session.get(Tenant, tenant_id)
        if t is None:
            t = Tenant(tenant_id=tenant_id, revocation_epoch=0)
            self.session.add(t)
            self.session.flush()
        return t

    # ------------------------------------------------------------ lookups
    def get_object(self, tenant_id: str, context_id: str, version: str) -> ContextObject | None:
        row = self.session.get(ContextObject, (context_id, version))
        if row is None or row.tenant_id != tenant_id:
            return None
        return row

    def get_versions(self, tenant_id: str, context_id: str) -> list[ContextObject]:
        stmt = select(ContextObject).where(
            ContextObject.tenant_id == tenant_id, ContextObject.context_id == context_id
        )
        return list(self.session.scalars(stmt))

    def load_objects(self, tenant_id: str, nodes: list[Node]) -> dict[Node, ContextObject]:
        if not nodes:
            return {}
        ids = {n[0] for n in nodes}
        stmt = select(ContextObject).where(
            ContextObject.tenant_id == tenant_id, ContextObject.context_id.in_(ids)
        )
        wanted = set(nodes)
        out: dict[Node, ContextObject] = {}
        for row in self.session.scalars(stmt):
            key = (row.context_id, row.object_version)
            if key in wanted:
                out[key] = row
        return out

    # ------------------------------------------------------------ registration
    def _insert_or_dedupe(self, env: ContextEnvelope) -> bool:
        """Return True if a new row must be inserted, False if an identical one exists."""
        existing = self.session.get(ContextObject, (env.context_id, env.object_version))
        if existing is None:
            return True
        if existing.tenant_id != env.tenant_id or existing.content_digest != env.content_digest:
            raise DuplicateContext(f"{env.context_id}@{env.object_version} already registered differently")
        return False

    def register_source(self, env: ContextEnvelope) -> ContextObject:
        if env.kind != Kind.SOURCE or env.parent_refs:
            raise InvalidEnvelope("register_source requires kind=source and no parent_refs")
        if not self._insert_or_dedupe(env):
            return self.session.get(ContextObject, (env.context_id, env.object_version))  # type: ignore[return-value]
        self.ensure_tenant(env.tenant_id)
        row = _row_from_envelope(env)
        self.session.add(row)
        self.session.flush()
        return row

    def register_derivation(self, env: ContextEnvelope) -> ContextObject:
        if env.kind == Kind.SOURCE or not env.parent_refs:
            raise InvalidEnvelope("register_derivation requires a non-source kind with parent_refs")
        parent_nodes: list[Node] = [(p.context_id, p.object_version) for p in env.parent_refs]
        parents = self.load_objects(env.tenant_id, parent_nodes)
        missing = [n for n in parent_nodes if n not in parents]
        if missing:
            raise LineageIncomplete(missing)
        if not self._insert_or_dedupe(env):
            return self.session.get(ContextObject, (env.context_id, env.object_version))  # type: ignore[return-value]
        computed = effective_authority(parents.values())
        check_not_wider(env, computed)
        self.ensure_tenant(env.tenant_id)
        row = _row_from_envelope(env)
        self.session.add(row)
        self.session.flush()
        for pid, pver in dict.fromkeys(parent_nodes):
            self.session.add(
                DerivationEdge(
                    child_id=env.context_id,
                    child_version=env.object_version,
                    parent_id=pid,
                    parent_version=pver,
                    tenant_id=env.tenant_id,
                )
            )
        self.session.flush()
        return row

    # ------------------------------------------------------------ traversal
    def _walk(self, tenant_id: str, context_id: str, version: str | None, up: bool) -> list[Node]:
        E = DerivationEdge
        if up:
            frm_id, frm_ver, to_id, to_ver = E.child_id, E.child_version, E.parent_id, E.parent_version
        else:
            frm_id, frm_ver, to_id, to_ver = E.parent_id, E.parent_version, E.child_id, E.child_version
        base_where = [E.tenant_id == tenant_id, frm_id == context_id]
        if version is not None:
            base_where.append(frm_ver == version)
        base = select(to_id.label("cid"), to_ver.label("ver")).where(*base_where)
        walk = base.cte("walk", recursive=True)
        step = (
            select(to_id, to_ver)
            .join(walk, and_(frm_id == walk.c.cid, frm_ver == walk.c.ver))
            .where(E.tenant_id == tenant_id)
        )
        walk = walk.union(step)
        rows = self.session.execute(select(walk.c.cid, walk.c.ver)).all()
        return sorted((r[0], r[1]) for r in rows)

    def get_ancestors(self, tenant_id: str, context_id: str, version: str) -> list[Node]:
        """All transitive parents (excluding the node itself)."""
        return self._walk(tenant_id, context_id, version, up=True)

    def get_descendants(self, tenant_id: str, context_id: str, version: str | None = None) -> list[Node]:
        """All transitive children; version=None starts from every version of context_id."""
        return self._walk(tenant_id, context_id, version, up=False)
