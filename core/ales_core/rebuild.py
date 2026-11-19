"""Transformation registry and rebuild workflow.

When a source is superseded, its derivatives (chunks, embeddings, summaries...) are stale. ALES does not
regenerate content; it records *which registered transformation* produced each derivative, plans which
derivatives must be recomputed from the new inputs, and runs integrator-supplied handlers to do the work.

The rule (from the product brief, "rebuild is a new derivation, never a reconnection"): **a rebuilt
derivative is always registered as a NEW object with a NEW derivation record pointing at the NEW parents.**
The old derivative is never re-parented, edited or "revalidated"; it keeps its old lineage and keeps
resolving REFRESH / DENY. There is no code path here that attaches old bytes to new parents. Because the new
object's authority is recomputed from its (new) parents and checked by the normal widening rule, a rebuild
can never launder authority either.

Flow::

    register_transformation(...)            # per tenant, immutable per (id, version)
    GraphStore.register_derivation(env, transformation=(id, ver))   # or tag_transformation
    ... a source version is superseded ...
    plan_rebuild(session, tenant, cid, ver)     -> [RebuildStep]    (read-only)
    enqueue_rebuild(session, tenant, cid, ver)  -> [RebuildJobRow]  (idempotent, audited)
    RebuildRunner(session_factory, handlers).run_once()              (leased, like the outbox)

ALES ships NO handlers and stores NO content. A handler receives descriptors of the current inputs
(:class:`RebuildInput`: ids, kind, digest) and returns the digest of the content it produced
(:class:`RebuildOutput`); it fetches input bytes from, and persists output bytes to, the integrator's own
store. A completed job registers the new derivative (unsigned, server-originated, ``successor_of`` = the old
derivative so the chain can continue) and cascades: derivatives of the old derivative are planned next.

Jobs of a transformation not declared ``idempotent`` are never retried after a handler error or a crashed
lease (the side effect might have happened); they fail with a clear error for an operator to decide.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Result, and_, or_, select, update
from sqlalchemy.orm import Session

from . import audit
from .db import DerivationEdge, RebuildJobRow, TransformationRow, lock_tenant, utcnow
from .exceptions import AlesError
from .graph import GraphStore, Node, find_successors
from .models import ContextEnvelope, Kind
from .propagation import effective_authority
from .tombstones import utc

REBUILD_ACTOR = "rebuild-worker"
MAX_ERROR_CHARS = 1000
DEFAULT_LEASE_SECONDS = 60
MAX_ATTEMPTS = 3
BACKOFF_SECONDS: tuple[int, ...] = (5, 30)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_NS = uuid.UUID("6b7e1b0e-2b1e-4f43-9c0d-5b1a7d1f2a10")  # deterministic ids for rebuilt derivatives
_KINDS = {k.value for k in Kind}


class RebuildError(AlesError):
    """Invalid transformation definition or an unplannable rebuild."""


def _rc(result: Result[Any]) -> int:
    return int(getattr(result, "rowcount", 0) or 0)


def register_transformation(
    session: Session,
    tenant: str,
    transformation_id: str,
    version: str,
    input_kinds: Sequence[str],
    output_kind: str,
    implementation_ref: str,
    idempotent: bool,
    *,
    actor: str,
    at: datetime | None = None,
) -> TransformationRow:
    """Register ``transformation_id@version`` for ``tenant`` (audited ``transformation.register``).

    Immutable: re-registering an identical definition returns the existing row, a different one raises
    :class:`RebuildError`. Does not commit."""
    if not transformation_id or len(transformation_id) > 255 or not version or len(version) > 64:
        raise RebuildError("transformation_id (<=255) and version (<=64) are required")
    kinds = list(dict.fromkeys(input_kinds))
    if not kinds or any(k not in _KINDS for k in kinds):
        raise RebuildError(f"input_kinds must be a non-empty subset of {sorted(_KINDS)}")
    if output_kind not in _KINDS or output_kind == Kind.SOURCE.value:
        raise RebuildError("output_kind must be a derivative kind")
    if not implementation_ref or len(implementation_ref) > 512:
        raise RebuildError("implementation_ref is required (<=512 chars)")
    lock_tenant(session, tenant)
    existing = get_transformation(session, tenant, transformation_id, version)
    if existing is not None:
        same = (
            list(existing.input_kinds) == kinds
            and existing.output_kind == output_kind
            and existing.implementation_ref == implementation_ref
            and bool(existing.idempotent) == bool(idempotent)
        )
        if not same:
            raise RebuildError(
                f"transformation {transformation_id}@{version} already registered with a different definition"
            )
        return existing
    when = utc(at) if at else utcnow()
    row = TransformationRow(
        tenant_id=tenant,
        transformation_id=transformation_id,
        version=version,
        input_kinds=kinds,
        output_kind=output_kind,
        implementation_ref=implementation_ref,
        idempotent=bool(idempotent),
        created_by=actor,
        created_at=when,
    )
    session.add(row)
    session.flush()
    audit.append(
        session,
        tenant,
        actor,
        "transformation.register",
        {
            "transformation_id": transformation_id,
            "version": version,
            "input_kinds": kinds,
            "output_kind": output_kind,
            "implementation_ref": implementation_ref,
            "idempotent": bool(idempotent),
        },
        at=when,
    )
    return row


def get_transformation(
    session: Session, tenant: str, transformation_id: str, version: str
) -> TransformationRow | None:
    return session.scalar(
        select(TransformationRow).where(
            TransformationRow.tenant_id == tenant,
            TransformationRow.transformation_id == transformation_id,
            TransformationRow.version == version,
        )
    )


def list_transformations(session: Session, tenant: str) -> list[TransformationRow]:
    return list(
        session.scalars(
            select(TransformationRow)
            .where(TransformationRow.tenant_id == tenant)
            .order_by(TransformationRow.transformation_id, TransformationRow.version)
        )
    )


@dataclass(frozen=True)
class RebuildStep:
    derivative: Node
    transformation: tuple[str, str]
    current_inputs: list[Node]


def _latest_successor(session: Session, graph: GraphStore, tenant: str, node: Node) -> Node | None:
    succ = find_successors(session, tenant, node[0], node[1])
    if not succ:
        return None
    rows = graph.load_objects(tenant, succ)
    live = [rows[n] for n in succ if n in rows]
    if not live:
        return None
    best = max(live, key=lambda r: (utc(r.valid_from), r.object_version))
    return (best.context_id, best.object_version)


def plan_rebuild(session: Session, tenant: str, context_id: str, version: str) -> list[RebuildStep]:
    """Read-only plan: the direct derivatives of the superseded node ``(context_id, version)`` that carry a
    registered transformation and have not been rebuilt, each with its *current* inputs (every parent replaced
    by its latest successor when it has one). Deeper derivatives are planned when their parent's rebuild
    completes (cascade). Returns ``[]`` when the node has no successor yet. Raises :class:`RebuildError` for an
    unknown (or foreign-tenant) object."""
    graph = GraphStore(session)
    if graph.get_object(tenant, context_id, version) is None:
        raise RebuildError(f"unknown object {context_id}@{version}")
    if _latest_successor(session, graph, tenant, (context_id, version)) is None:
        return []
    edges = list(
        session.scalars(
            select(DerivationEdge).where(
                DerivationEdge.tenant_id == tenant,
                DerivationEdge.parent_id == context_id,
                DerivationEdge.parent_version == version,
            )
        )
    )
    children = sorted({(e.child_id, e.child_version) for e in edges})
    rows = graph.load_objects(tenant, children)
    steps: list[RebuildStep] = []
    for child in children:
        row = rows.get(child)
        if row is None or row.transformation_id is None or row.transformation_version is None:
            continue
        if find_successors(session, tenant, child[0], child[1]):
            continue  # already rebuilt (or replaced some other way)
        parents = sorted(
            {
                (e.parent_id, e.parent_version)
                for e in session.scalars(
                    select(DerivationEdge).where(
                        DerivationEdge.tenant_id == tenant,
                        DerivationEdge.child_id == child[0],
                        DerivationEdge.child_version == child[1],
                    )
                )
            }
        )
        inputs: list[Node] = []
        for p in parents:
            current = _latest_successor(session, graph, tenant, p) or p
            if current not in inputs:
                inputs.append(current)
        if inputs == parents:
            continue
        steps.append(RebuildStep(child, (row.transformation_id, row.transformation_version), inputs))
    return steps


def _inputs_key(step: RebuildStep) -> str:
    document = {
        "derivative": list(step.derivative),
        "transformation": list(step.transformation),
        "inputs": sorted(list(n) for n in step.current_inputs),
    }
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def enqueue_rebuild(
    session: Session,
    tenant: str,
    context_id: str,
    version: str,
    *,
    actor: str,
    now: datetime | None = None,
) -> list[RebuildJobRow]:
    """Plan and persist one job per step; return every job for the plan (new and pre-existing). Idempotent on
    the (derivative, transformation, inputs) key; a previously *failed* job for the same step is reset to
    ``pending`` so re-enqueueing after fixing a handler retries it. Audited ``rebuild.enqueue`` when any step
    exists. Does not commit."""
    when = utc(now) if now else utcnow()
    lock_tenant(session, tenant)
    steps = plan_rebuild(session, tenant, context_id, version)
    jobs: list[RebuildJobRow] = []
    created = 0
    for step in steps:
        key = _inputs_key(step)
        job = session.scalar(
            select(RebuildJobRow).where(RebuildJobRow.tenant_id == tenant, RebuildJobRow.inputs_key == key)
        )
        if job is None:
            job = RebuildJobRow(
                tenant_id=tenant,
                superseded_context_id=context_id,
                superseded_version=version,
                derivative_context_id=step.derivative[0],
                derivative_version=step.derivative[1],
                transformation_id=step.transformation[0],
                transformation_version=step.transformation[1],
                inputs=[list(n) for n in step.current_inputs],
                inputs_key=key,
                state="pending",
                attempts=0,
                available_at=when,
                created_by=actor,
                created_at=when,
            )
            session.add(job)
            created += 1
        elif job.state == "failed":
            job.state, job.attempts, job.last_error, job.available_at = "pending", 0, None, when
            job.lease_token = job.lease_expires_at = None
            created += 1
        jobs.append(job)
    session.flush()
    if steps:
        audit.append(
            session,
            tenant,
            actor,
            "rebuild.enqueue",
            {"context_id": context_id, "version": version[:255], "planned": len(steps), "queued": created},
            at=when,
        )
    return jobs


def list_jobs(
    session: Session, tenant: str, *, state: str | None = None, limit: int = 100, after_id: int = 0
) -> list[RebuildJobRow]:
    statement = select(RebuildJobRow).where(RebuildJobRow.tenant_id == tenant, RebuildJobRow.id > after_id)
    if state is not None:
        statement = statement.where(RebuildJobRow.state == state)
    return list(session.scalars(statement.order_by(RebuildJobRow.id).limit(limit)))


@dataclass(frozen=True)
class RebuildInput:
    """Descriptor of one current input handed to a handler (identifiers and digest, never content)."""

    context_id: str
    object_version: str
    kind: str
    content_digest: str
    object_id: str


@dataclass(frozen=True)
class RebuildOutput:
    """What a handler produced: the ``sha256:<hex>`` digest of the new content (which the handler has
    persisted in its own store) and, optionally, a new ``object_id`` label."""

    content_digest: str
    object_id: str | None = None


RebuildHandler = Callable[[Sequence[RebuildInput]], RebuildOutput]


@dataclass(frozen=True)
class RebuildRunResult:
    leased: int = 0
    done: int = 0
    failed: int = 0  # terminal
    retried: int = 0
    lost_lease: int = 0


class RebuildRunner:
    """Leases due jobs (compare-and-swap, like the outbox) and runs the registered handler per transformation.

    ``handlers`` maps ``transformation_id`` -> callable. ``tenant_id`` restricts the runner to one tenant."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        handlers: Mapping[str, RebuildHandler],
        *,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        max_attempts: int = MAX_ATTEMPTS,
        tenant_id: str | None = None,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self.session_factory = session_factory
        self.handlers = dict(handlers)
        self.lease_seconds = lease_seconds
        self.max_attempts = max_attempts
        self.tenant_id = tenant_id

    def _leasable(self, now: datetime) -> Any:
        cond = or_(
            and_(RebuildJobRow.state == "pending", RebuildJobRow.available_at <= now),
            and_(RebuildJobRow.state == "leased", RebuildJobRow.lease_expires_at <= now),
        )
        return and_(cond, RebuildJobRow.tenant_id == self.tenant_id) if self.tenant_id else cond

    def _lease(self, now: datetime, batch: int, token: str) -> list[int]:
        leased: list[int] = []
        with self.session_factory() as s:
            ids = list(
                s.scalars(
                    select(RebuildJobRow.id)
                    .where(self._leasable(now))
                    .order_by(RebuildJobRow.available_at, RebuildJobRow.id)
                    .limit(batch)
                )
            )
            for rid in ids:
                won = _rc(
                    s.execute(
                        update(RebuildJobRow)
                        .where(RebuildJobRow.id == rid, self._leasable(now))
                        .values(
                            state="leased",
                            lease_token=token,
                            lease_expires_at=now + timedelta(seconds=self.lease_seconds),
                            attempts=RebuildJobRow.attempts + 1,
                        )
                    )
                )
                if won:
                    leased.append(rid)
            s.commit()
        return leased

    def run_once(self, now: datetime | None = None, batch_size: int = 20) -> RebuildRunResult:
        when = utc(now) if now else datetime.now(UTC)
        token = uuid.uuid4().hex
        ids = self._lease(when, batch_size, token)
        if not ids:
            return RebuildRunResult()
        with self.session_factory() as s:
            jobs = list(
                s.scalars(
                    select(RebuildJobRow)
                    .where(RebuildJobRow.id.in_(ids), RebuildJobRow.lease_token == token)
                    .order_by(RebuildJobRow.id)
                )
            )
            s.expunge_all()
        counts = {"done": 0, "failed": 0, "retried": 0, "lost": 0}
        for job in jobs:
            counts[self._process(job, token, when)] += 1
        return RebuildRunResult(
            leased=len(jobs),
            done=counts["done"],
            failed=counts["failed"],
            retried=counts["retried"],
            lost_lease=counts["lost"],
        )

    def _process(self, job: RebuildJobRow, token: str, now: datetime) -> str:
        with self.session_factory() as s:
            tr = get_transformation(s, job.tenant_id, job.transformation_id, job.transformation_version)
            idempotent = bool(tr.idempotent) if tr is not None else False
        if tr is None:
            return self._fail(job, token, now, "transformation is not registered", retryable=False)
        handler = self.handlers.get(job.transformation_id)
        if handler is None:
            return self._fail(
                job,
                token,
                now,
                f"no rebuild handler registered for transformation {job.transformation_id!r}; "
                "register one with create_app(rebuild_handlers={...})",
                retryable=False,
            )
        if job.attempts > 1 and not idempotent:
            return self._fail(
                job,
                token,
                now,
                "previous attempt did not complete and the transformation is not idempotent; not retried",
                retryable=False,
            )
        try:
            inputs = self._load_inputs(job)
            result = handler(inputs)
            if not isinstance(result, RebuildOutput) or not _DIGEST.match(result.content_digest or ""):
                raise RebuildError("handler must return RebuildOutput with content_digest 'sha256:<64 hex>'")
        except Exception as exc:  # noqa: BLE001 - a handler failure must never abort the batch
            return self._fail(
                job,
                token,
                now,
                f"{type(exc).__name__}: {exc}",
                retryable=idempotent and job.attempts < self.max_attempts,
            )
        try:
            return self._complete(job, token, now, result)
        except Exception as exc:  # noqa: BLE001 - e.g. AuthorityWidening, LineageIncomplete
            return self._fail(job, token, now, f"{type(exc).__name__}: {exc}", retryable=False)

    def _load_inputs(self, job: RebuildJobRow) -> list[RebuildInput]:
        with self.session_factory() as s:
            nodes = [(str(c), str(v)) for c, v in job.inputs]
            rows = GraphStore(s).load_objects(job.tenant_id, nodes)
            missing = [n for n in nodes if n not in rows]
            if missing:
                raise RebuildError(f"input object(s) no longer registered: {missing}")
            return [
                RebuildInput(r.context_id, r.object_version, r.kind, r.content_digest, r.object_id)
                for r in (rows[n] for n in nodes)
            ]

    def _guard(self, job: RebuildJobRow, token: str) -> tuple[Any, ...]:
        return (
            RebuildJobRow.id == job.id,
            RebuildJobRow.lease_token == token,
            RebuildJobRow.state == "leased",
        )

    def _fail(self, job: RebuildJobRow, token: str, now: datetime, err: str, *, retryable: bool) -> str:
        err = err[:MAX_ERROR_CHARS]
        with self.session_factory() as s:
            if retryable:
                delay = BACKOFF_SECONDS[min(job.attempts, len(BACKOFF_SECONDS)) - 1]
                n = _rc(
                    s.execute(
                        update(RebuildJobRow)
                        .where(*self._guard(job, token))
                        .values(
                            state="pending",
                            lease_token=None,
                            lease_expires_at=None,
                            last_error=err,
                            available_at=now + timedelta(seconds=delay),
                        )
                    )
                )
                outcome = "retried"
            else:
                n = _rc(
                    s.execute(
                        update(RebuildJobRow)
                        .where(*self._guard(job, token))
                        .values(state="failed", lease_token=None, lease_expires_at=None, last_error=err)
                    )
                )
                outcome = "failed"
                if n:
                    audit.append(
                        s,
                        job.tenant_id,
                        REBUILD_ACTOR,
                        "rebuild.failed",
                        {
                            "job_id": job.id,
                            "derivative": job.derivative_context_id,
                            "version": job.derivative_version[:255],
                            "transformation_id": job.transformation_id,
                            "error": err[:300],
                        },
                        at=now,
                    )
            s.commit()
        return outcome if n else "lost"

    def _complete(self, job: RebuildJobRow, token: str, now: datetime, out: RebuildOutput) -> str:
        with self.session_factory() as s:
            try:
                lock_tenant(s, job.tenant_id)
                new_cid = str(uuid.uuid5(_NS, f"{job.tenant_id}:{job.id}:{job.inputs_key}"))
                new_ver = f"{job.derivative_version}+r{job.id}"
                won = _rc(
                    s.execute(
                        update(RebuildJobRow)
                        .where(*self._guard(job, token))
                        .values(
                            state="done",
                            lease_token=None,
                            lease_expires_at=None,
                            last_error=None,
                            result_context_id=new_cid,
                            result_version=new_ver,
                        )
                    )
                )
                if not won:
                    s.rollback()
                    return "lost"
                graph = GraphStore(s)
                old = graph.get_object(job.tenant_id, job.derivative_context_id, job.derivative_version)
                tr = get_transformation(s, job.tenant_id, job.transformation_id, job.transformation_version)
                if old is None or tr is None:
                    raise RebuildError("derivative or transformation vanished")
                if old.kind != tr.output_kind:
                    raise RebuildError(
                        f"derivative kind {old.kind!r} != transformation output_kind {tr.output_kind!r}"
                    )
                nodes = [(str(c), str(v)) for c, v in job.inputs]
                parents = graph.load_objects(job.tenant_id, nodes)
                if any(n not in parents for n in nodes):
                    raise RebuildError("an input object is no longer registered")
                eff = effective_authority(parents.values())
                env = ContextEnvelope.model_validate(
                    {
                        "context_id": new_cid,
                        "tenant_id": job.tenant_id,
                        "object_id": (out.object_id or old.object_id),
                        "object_version": new_ver,
                        "content_digest": out.content_digest,
                        "kind": old.kind,
                        "source_system": old.source_system,
                        "source_acl_ref": old.source_acl_ref,
                        "principal_scope": None
                        if eff.principal_scope is None
                        else sorted(eff.principal_scope),
                        "purpose_scope": None if eff.purpose_scope is None else sorted(eff.purpose_scope),
                        "classification": eff.classification.value,
                        "trust_state": eff.trust_state.value,
                        "parent_refs": [{"context_id": c, "object_version": v} for c, v in nodes],
                        "policy_version": old.policy_version,
                        "valid_from": now,
                        "expires_at": eff.expires_at,
                        "successor_of": {"context_id": old.context_id, "object_version": old.object_version},
                    }
                )
                # ALWAYS a new derivation record over the NEW parents; the old derivative is untouched.
                graph.register_derivation(
                    env, transformation=(job.transformation_id, job.transformation_version)
                )
                audit.append(
                    s,
                    job.tenant_id,
                    REBUILD_ACTOR,
                    "rebuild.complete",
                    {
                        "job_id": job.id,
                        "derivative": old.context_id,
                        "derivative_version": old.object_version[:255],
                        "result": new_cid,
                        "result_version": new_ver[:255],
                        "transformation_id": job.transformation_id,
                        "transformation_version": job.transformation_version,
                        "inputs": [[c, v[:255]] for c, v in nodes[:20]],
                    },
                    at=now,
                )
                # Cascade: derivatives OF the old derivative now have a rebuilt parent to move to.
                enqueue_rebuild(
                    s, job.tenant_id, old.context_id, old.object_version, actor=REBUILD_ACTOR, now=now
                )
                s.commit()
            except Exception:
                s.rollback()
                raise
        return "done"


__all__ = [
    "RebuildError",
    "RebuildHandler",
    "RebuildInput",
    "RebuildOutput",
    "RebuildRunResult",
    "RebuildRunner",
    "RebuildStep",
    "enqueue_rebuild",
    "get_transformation",
    "list_jobs",
    "list_transformations",
    "plan_rebuild",
    "register_transformation",
]
