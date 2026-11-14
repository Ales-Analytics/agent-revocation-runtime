"""Lineage graph store. Every query is partitioned by tenant_id."""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from .db import ContextObject, DerivationEdge, Tenant, TransformationRow, lock_tenant
from .exceptions import DuplicateContext, InvalidEnvelope, LineageIncomplete
from .models import ContextEnvelope, Kind
from .propagation import check_not_wider, effective_authority
from .tombstones import materialize_pending

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
        principal_scope=None if env.principal_scope is None else list(env.principal_scope),
        purpose_scope=None if env.purpose_scope is None else list(env.purpose_scope),
        valid_from=env.valid_from,
        expires_at=env.expires_at,
        source_system=env.source_system,
        source_acl_ref=env.source_acl_ref,
        policy_version=env.policy_version,
        signature=env.signature,
        issuer_key_id=env.issuer_key_id,
        successor_context_id=env.successor_of.context_id if env.successor_of else None,
        successor_version=env.successor_of.object_version if env.successor_of else None,
        tombstoned=False,
        tombstone_reason=None,
    )


def _scope_canon(v: list[str] | None) -> list[str] | None:
    return None if v is None else sorted(set(v))


def _semantic_diff(session: Session, row: ContextObject, env: ContextEnvelope) -> list[str]:
    """Names of canonical semantic fields on which a stored row differs from an envelope."""
    diffs: list[str] = []
    if row.tenant_id != env.tenant_id:
        diffs.append("tenant_id")
    if row.content_digest != env.content_digest:
        diffs.append("content_digest")
    if row.kind != env.kind.value:
        diffs.append("kind")
    if row.classification != env.classification.value:
        diffs.append("classification")
    if row.trust_state != env.trust_state.value:
        diffs.append("trust_state")
    if _scope_canon(row.principal_scope) != _scope_canon(env.principal_scope):
        diffs.append("principal_scope")
    if _scope_canon(row.purpose_scope) != _scope_canon(env.purpose_scope):
        diffs.append("purpose_scope")
    if row.valid_from != env.valid_from:
        diffs.append("valid_from")
    if row.expires_at != env.expires_at:
        diffs.append("expires_at")
    env_succ = (env.successor_of.context_id, env.successor_of.object_version) if env.successor_of else None
    row_succ = (
        (row.successor_context_id, row.successor_version or "") if row.successor_context_id is not None else None
    )
    if row_succ != env_succ:
        diffs.append("successor_of")
    stored_parents = {
        (e.parent_id, e.parent_version)
        for e in session.scalars(
            select(DerivationEdge).where(
                DerivationEdge.child_id == row.context_id,
                DerivationEdge.child_version == row.object_version,
            )
        )
    }
    if stored_parents != {(p.context_id, p.object_version) for p in env.parent_refs}:
        diffs.append("parent_refs")
    return diffs


@dataclass
class GraphReport:
    """Result of :func:`verify_graph`; every list is empty for a healthy graph."""

    orphan_edges: list[tuple[Node, Node]] = field(default_factory=list)  # (child, parent): child missing
    missing_parents: list[tuple[Node, Node]] = field(default_factory=list)  # (child, parent): parent missing
    cycle_suspects: list[Node] = field(default_factory=list)  # nodes on, or between, cycles
    dangling_successors: list[tuple[Node, Node]] = field(default_factory=list)  # (object, absent successor)

    @property
    def ok(self) -> bool:
        return not (
            self.orphan_edges or self.missing_parents or self.cycle_suspects or self.dangling_successors
        )


def verify_graph(session: Session, tenant_id: str) -> GraphReport:
    """Integrity scan of one tenant's lineage graph using set queries (no recursive traversal).

    Cycle detection peels edges whose child has no remaining children or whose parent has no remaining
    parents (Kahn's algorithm from both ends); whatever survives lies on, or between, cycles. Endpoints
    that exist only under another tenant count as missing (they are never traversed)."""
    nodes: dict[Node, tuple[str | None, str | None]] = {
        (r[0], r[1]): (r[2], r[3])
        for r in session.execute(
            select(
                ContextObject.context_id,
                ContextObject.object_version,
                ContextObject.successor_context_id,
                ContextObject.successor_version,
            ).where(ContextObject.tenant_id == tenant_id)
        )
    }
    report = GraphReport()
    good: set[tuple[Node, Node]] = set()
    for e in session.scalars(select(DerivationEdge).where(DerivationEdge.tenant_id == tenant_id)):
        child, parent = (e.child_id, e.child_version), (e.parent_id, e.parent_version)
        if child not in nodes:
            report.orphan_edges.append((child, parent))
        elif parent not in nodes:
            report.missing_parents.append((child, parent))
        else:
            good.add((child, parent))
    for node, (sc, sv) in nodes.items():
        if sc is not None and (sc, sv or "") not in nodes:
            report.dangling_successors.append((node, (sc, sv or "")))
    remaining = set(good)
    while remaining:
        children = {c for c, _ in remaining}
        parents = {p for _, p in remaining}
        peel = {(c, p) for c, p in remaining if c not in parents or p not in children}
        if not peel:
            break
        remaining -= peel
    report.cycle_suspects = sorted({n for edge in remaining for n in edge})
    report.orphan_edges.sort()
    report.missing_parents.sort()
    report.dangling_successors.sort()
    return report


def find_successors(session: Session, tenant_id: str, context_id: str, version: str) -> list[Node]:
    """Objects that supersede ``(context_id, version)``, transitively, in stable sorted order.

    Follows ``successor_of`` links (a replacement registered under a NEW context_id) and newer versions
    of the same context_id (later ``valid_from``, ties by version string). The node itself is never
    returned. Read-only and tenant-scoped."""
    seen: set[Node] = {(context_id, version)}
    out: list[Node] = []
    frontier: list[Node] = [(context_id, version)]
    while frontier:
        cid, ver = frontier.pop()
        found: list[Node] = [
            (r.context_id, r.object_version)
            for r in session.scalars(
                select(ContextObject).where(
                    ContextObject.tenant_id == tenant_id,
                    ContextObject.successor_context_id == cid,
                    ContextObject.successor_version == ver,
                )
            )
        ]
        base = session.get(ContextObject, (cid, ver))
        if base is not None and base.tenant_id == tenant_id:
            for r in session.scalars(
                select(ContextObject).where(
                    ContextObject.tenant_id == tenant_id, ContextObject.context_id == cid
                )
            ):
                if (r.valid_from, r.object_version) > (base.valid_from, base.object_version):
                    found.append((r.context_id, r.object_version))
        for n in found:
            if n not in seen:
                seen.add(n)
                out.append(n)
                frontier.append(n)
    return sorted(out)


class GraphStore:
    def __init__(self, session: Session):
        self.session = session

    # ---------------------------------------------------------------- tenants
    def ensure_tenant(self, tenant_id: str) -> Tenant:
        """Create-if-absent and lock the tenant row (see :func:`ales_core.db.lock_tenant`)."""
        return lock_tenant(self.session, tenant_id)

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
        # Registration is immutable (v0.4): a duplicate is a no-op only when the canonical semantic
        # metadata is identical; any difference is a conflict.
        diffs = _semantic_diff(self.session, existing, env)
        if diffs:
            raise DuplicateContext(
                f"{env.context_id}@{env.object_version} already registered differently ({', '.join(diffs)})"
            )
        return False

    def register_source(self, env: ContextEnvelope) -> ContextObject:
        if env.kind != Kind.SOURCE or env.parent_refs:
            raise InvalidEnvelope("register_source requires kind=source and no parent_refs")
        self.ensure_tenant(env.tenant_id)  # lock first: the check-then-insert below is then race-free
        if not self._insert_or_dedupe(env):
            return self.session.get(ContextObject, (env.context_id, env.object_version))  # type: ignore[return-value]
        row = _row_from_envelope(env)
        self.session.add(row)
        self.session.flush()
        materialize_pending(self.session, row)
        return row

    def _require_transformation(self, tenant_id: str, transformation: tuple[str, str]) -> None:
        t = self.session.scalar(
            select(TransformationRow.id).where(
                TransformationRow.tenant_id == tenant_id,
                TransformationRow.transformation_id == transformation[0],
                TransformationRow.version == transformation[1],
            )
        )
        if t is None:
            raise InvalidEnvelope(f"transformation {transformation[0]}@{transformation[1]} is not registered")

    def tag_transformation(
        self, tenant_id: str, context_id: str, version: str, transformation: tuple[str, str]
    ) -> ContextObject:
        """Record which registered transformation produced an already-registered derivative. Set-once:
        re-tagging with the same value is a no-op, a different value raises :class:`DuplicateContext`.
        Lifecycle metadata only (never part of the envelope or a decision)."""
        row = self.get_object(tenant_id, context_id, version)
        if row is None:
            raise InvalidEnvelope(f"unknown object {context_id}@{version}")
        if row.kind == Kind.SOURCE.value:
            raise InvalidEnvelope("a source has no transformation")
        self._require_transformation(tenant_id, transformation)
        current = (row.transformation_id, row.transformation_version)
        if current == (None, None):
            row.transformation_id, row.transformation_version = transformation
            self.session.flush()
        elif current != transformation:
            raise DuplicateContext(
                f"{context_id}@{version} already tagged with transformation {current[0]}@{current[1]}"
            )
        return row

    def register_derivation(
        self, env: ContextEnvelope, *, transformation: tuple[str, str] | None = None
    ) -> ContextObject:
        """Register a derivative. ``transformation=(id, version)`` (additive, not part of the envelope) names
        the registered transformation that produced it; it is validated against the tenant registry and stored
        on the object row for the rebuild planner. A deduplicated re-registration keeps the first tag."""
        if env.kind == Kind.SOURCE or not env.parent_refs:
            raise InvalidEnvelope("register_derivation requires a non-source kind with parent_refs")
        self.ensure_tenant(env.tenant_id)  # lock first (see register_source)
        if transformation is not None:
            self._require_transformation(env.tenant_id, transformation)
        parent_nodes: list[Node] = [(p.context_id, p.object_version) for p in env.parent_refs]
        parents = self.load_objects(env.tenant_id, parent_nodes)
        missing = [n for n in parent_nodes if n not in parents]
        if missing:
            raise LineageIncomplete(missing)
        if not self._insert_or_dedupe(env):
            return self.session.get(ContextObject, (env.context_id, env.object_version))  # type: ignore[return-value]
        computed = effective_authority(parents.values())
        check_not_wider(env, computed)
        row = _row_from_envelope(env)
        if transformation is not None:
            row.transformation_id, row.transformation_version = transformation
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
        materialize_pending(self.session, row)
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
