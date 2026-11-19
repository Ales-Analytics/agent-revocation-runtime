"""Lifecycle value layer: impact preview, decision explanation, transformation registry + rebuilds, durable
sessions. See ``docs/lifecycle.md``.

Same conventions as ``routes.py``: every route declares its role, binds its tenant to the credential with
``bind_tenant`` and answers 404 (never 403) for objects, traces, sessions or jobs of another tenant, so none
of these endpoints is a cross-tenant existence oracle. Mutations and their audit records commit together.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from ales_core import (
    AuditLog,
    DuplicateContext,
    GraphStore,
    InvalidationOutbox,
    Principal,
    RebuildError,
    RebuildJobRow,
    RebuildRunner,
    SessionError,
    Tenant,
    audit_append,
    enqueue_rebuild,
    exposed_sessions,
    get_session_view,
    get_transformation,
    has_any_exposures,
    list_jobs,
    list_transformations,
    record_exposure,
    register_transformation,
    reset_session,
)
from ales_core.db import DerivationEdge
from ales_core.resolver import principal_in_scope
from ales_core.tombstones import covers_node, load_tombstones, utc
from fastapi import APIRouter, HTTPException, Path, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import Identity, bind_tenant
from .config import ConfigError
from .routes import AdminDep, IngestDep, ReadDep, SessionDep

router = APIRouter(prefix="/v1")

Short = Annotated[str, StringConstraints(min_length=1, max_length=255)]
Node = tuple[str, str]

UNINSTRUMENTED_NOTE = (
    "ALES knows only what was registered with it and what hosts reported. Copies of this content in stores, "
    "caches, prompts, transcripts, exports or other systems that were never instrumented (no registration, no "
    "purge handler, no exposure report) are not listed here and are not touched by a revocation."
)
MAX_IMPACT_SESSION_IDS = 100
MAX_PATHS_PER_OBJECT = 10
MAX_PATH_DEPTH = 64
MAX_CLEANUP_ROWS = 200
DEFAULT_SESSION_RETENTION = timedelta(days=7)
MAX_SESSION_RETENTION = timedelta(days=366)
_DURATION = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")


def parse_duration(text: str | None, default: timedelta = DEFAULT_SESSION_RETENTION) -> timedelta:
    """``"7d"``, ``"12h"``, ``"30m"``, ``"90s"`` or bare seconds. Blank -> ``default``. Invalid or out of
    range (``<= 0`` or more than 366 days) raises :class:`ConfigError` (fail closed)."""
    if text is None or not text.strip():
        return default
    m = _DURATION.match(text)
    if not m:
        raise ConfigError(f"invalid duration {text!r} (use e.g. 7d, 12h, 30m, 90s)")
    secs = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    result = timedelta(seconds=secs)
    if result <= timedelta(0) or result > MAX_SESSION_RETENTION:
        raise ConfigError(f"duration {text!r} must be between 1 second and 366 days")
    return result


def _iso(dt: datetime | None) -> str | None:
    return utc(dt).strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt is not None else None


def _node(n: Node, kinds: Mapping[Node, str]) -> dict[str, Any]:
    return {"context_id": n[0], "object_version": n[1], "kind": kinds.get(n)}


@router.get("/impact/{context_id}")
def impact_preview(
    request: Request,
    context_id: str,
    version: str | None = Query(default=None, max_length=255),
    session: Session = SessionDep,
    ident: Identity = ReadDep,
) -> dict[str, Any]:
    """What revoking ``context_id`` (one ``version``, or every version) would touch. Read-only apart from the
    ``impact.preview`` audit record. Honest about its limits: ``exposed_sessions`` is ``unknown`` when the
    tenant has reported no sessions, and ``uninstrumented_note`` says what ALES cannot see."""
    tenant = bind_tenant(ident)
    state = request.app.state
    now: datetime = state.clock()
    graph = GraphStore(session)
    roots = graph.get_versions(tenant, context_id)
    if version is not None:
        roots = [r for r in roots if r.object_version == version]
    if not roots:
        raise HTTPException(404, detail={"error": "unknown_context", "context_id": context_id})
    root_nodes: list[Node] = sorted((r.context_id, r.object_version) for r in roots)
    desc: dict[Node, None] = {}
    for r in roots:
        for n in graph.get_descendants(tenant, r.context_id, r.object_version):
            if n not in root_nodes:
                desc[n] = None
    desc_rows = graph.load_objects(tenant, list(desc))
    kinds: dict[Node, str] = {n: row.kind for n, row in desc_rows.items()}
    kinds.update({(r.context_id, r.object_version): r.kind for r in roots})
    all_nodes: list[Node] = root_nodes + sorted(desc)
    node_set = set(all_nodes)

    ids = exposed_sessions(session, tenant, all_nodes, now)
    if ids:
        exposed: dict[str, Any] = {
            "status": "recorded",
            "count": len(ids),
            "ids": ids[:MAX_IMPACT_SESSION_IDS],
        }
        exposed["truncated"] = len(ids) > MAX_IMPACT_SESSION_IDS
    elif has_any_exposures(session, tenant, now):
        exposed = {"status": "none", "count": 0, "ids": [], "truncated": False}
    else:
        exposed = {"status": "unknown", "count": None, "ids": [], "truncated": False}

    cleanup_rows: list[InvalidationOutbox] = []
    cids = sorted({c for c, _ in all_nodes})
    for i in range(0, len(cids), 400):
        for ob in session.scalars(
            select(InvalidationOutbox).where(
                InvalidationOutbox.tenant_id == tenant,
                InvalidationOutbox.context_id.in_(cids[i : i + 400]),
                InvalidationOutbox.state != "done",
            )
        ):
            if (ob.context_id, ob.version) in node_set:
                cleanup_rows.append(ob)
    by_state: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    for ob in cleanup_rows:
        by_state[ob.state] = by_state.get(ob.state, 0) + 1
        by_kind[ob.store_kind] = by_kind.get(ob.store_kind, 0) + 1

    rebuildable: list[dict[str, Any]] = []
    registry: dict[tuple[str, str], bool] = {}
    for n in sorted(desc):
        row = desc_rows.get(n)
        if row is None or row.transformation_id is None or row.transformation_version is None:
            continue
        key = (row.transformation_id, row.transformation_version)
        if key not in registry:
            registry[key] = get_transformation(session, tenant, key[0], key[1]) is not None
        if registry[key]:
            rebuildable.append(
                {
                    "context_id": n[0],
                    "object_version": n[1],
                    "transformation_id": key[0],
                    "transformation_version": key[1],
                }
            )

    epoch = session.scalar(select(Tenant.revocation_epoch).where(Tenant.tenant_id == tenant)) or 0
    result = {
        "source": {
            "context_id": context_id,
            "versions": [
                {
                    "object_version": r.object_version,
                    "kind": r.kind,
                    "object_id": r.object_id,
                    "source_system": r.source_system,
                    "classification": r.classification,
                }
                for r in sorted(roots, key=lambda r: r.object_version)
            ],
        },
        "descendants": [_node(n, kinds) for n in sorted(desc)],
        "stores": sorted(set(kinds.values())),
        "exposed_sessions": exposed,
        "pending_cleanup": {"count": len(cleanup_rows), "by_state": by_state, "by_store_kind": by_kind},
        "uninstrumented_note": UNINSTRUMENTED_NOTE,
        "rebuildable": rebuildable,
        "revocation_epoch": int(epoch),
    }
    try:
        audit_append(
            session,
            tenant,
            ident.subject,
            "impact.preview",
            {
                "context_id": context_id[:255],
                "version": version[:255] if version else None,
                "descendants": len(desc),
                "exposed_sessions": exposed["count"],
                "pending_cleanup": len(cleanup_rows),
                "rebuildable": len(rebuildable),
            },
            at=now,
        )
        session.commit()
    except Exception:
        session.rollback()
        raise
    return result


def _explain_object(
    session: Session, graph: GraphStore, tenant: str, row: AuditLog, obj: dict[str, Any]
) -> dict[str, Any]:
    d = row.detail
    context_id, version = obj["context_id"], obj.get("version")
    result: dict[str, Any] = {
        "context_id": context_id,
        "version": version,
        "decision": obj["decision"],
        "reasons": obj.get("reason", []),
        "dependency_paths": [],
        "causes": [],
    }
    if version is None or obj["decision"] == "ALLOW":
        return result
    leaf: Node = (context_id, version)
    lineage: list[Node] = [leaf] + graph.get_ancestors(tenant, context_id, version)
    loaded = graph.load_objects(tenant, lineage)
    if leaf not in loaded:
        return result
    groups = (d.get("policy") or {}).get("groups") or []
    principal = d.get("principal") or {}
    pid = str(principal.get("id", ""))
    issuer = (d.get("policy") or {}).get("principal_issuer")
    purpose = d.get("purpose")
    at = utc(row.at)
    causal: dict[Node, list[Any]] = {}
    for t in load_tombstones(session, tenant, {n[0] for n in lineage}):
        if utc(t.effective_at) > at:
            continue  # not yet in effect when the decision was made
        if t.scope_principals and not principal_in_scope(t.scope_principals, pid, issuer, groups):
            continue
        if t.scope_purposes and purpose not in t.scope_purposes:
            continue
        for n in lineage:
            if n in loaded and covers_node(t, n[0], n[1]):
                causal.setdefault(n, []).append(t)
    parents: dict[Node, list[Node]] = {}
    for i in range(0, len(lineage), 300):
        chunk = lineage[i : i + 300]
        for e in session.scalars(
            select(DerivationEdge).where(
                DerivationEdge.tenant_id == tenant, DerivationEdge.child_id.in_([c for c, _ in chunk])
            )
        ):
            child = (e.child_id, e.child_version)
            if child in loaded:
                parents.setdefault(child, []).append((e.parent_id, e.parent_version))
    # fallback when no revocation explains the verdict (scope / policy / workload): the roots of the lineage
    targets = set(causal) or {n for n in lineage if not [p for p in parents.get(n, []) if p in loaded]}
    paths: list[list[Node]] = []
    stack: list[tuple[Node, list[Node]]] = [(leaf, [leaf])]
    while stack and len(paths) < MAX_PATHS_PER_OBJECT:
        node, path = stack.pop()
        if node in targets:
            paths.append(list(reversed(path)))
            continue
        if len(path) >= MAX_PATH_DEPTH:
            continue
        for p in sorted(parents.get(node, []), reverse=True):
            if p in loaded and p not in path:
                stack.append((p, [*path, p]))
    paths.sort()
    result["dependency_paths"] = [
        [_node(n, {k: v.kind for k, v in loaded.items()}) for n in p] for p in paths
    ]
    for n in sorted(causal):
        for t in causal[n]:
            result["causes"].append(
                {
                    "context_id": n[0],
                    "object_version": n[1],
                    "reason": t.reason,
                    "event_id": t.event_id,
                    "effective_at": _iso(t.effective_at),
                    "scoped": t.scoped,
                }
            )
    return result


def _render_text(expl: dict[str, Any]) -> str:
    lines = [f"Decision: {expl['decision']}  (trace {expl['trace_id']}, {expl['at']})"]
    shown = False
    for o in expl["objects"]:
        if o["decision"] == "ALLOW":
            continue
        shown = True
        lines.append("")
        lines.append(f"Object: {o['context_id']}@{o['version']} -> {o['decision']}")
        for c in o["causes"]:
            lines.append(
                f"  Dependent source: {c['context_id']}@{c['object_version']} "
                f"(revoked: {c['reason']} at {c['effective_at']}{', scoped' if c['scoped'] else ''})"
            )
        lines.append(f"  Reason: {', '.join(o['reasons']) or '-'}")
        for p in o["dependency_paths"]:
            lines.append(
                "  Dependency path: "
                + " -> ".join(f"{n['context_id']}@{n['object_version']} ({n['kind']})" for n in p)
            )
    if not shown:
        lines.append(f"Reason: {', '.join(expl['reasons'])}")
    a = expl["authority"]
    auth = f"revocation epoch {a['revocation_epoch']} (now {a['current_revocation_epoch']}), policy {a['policy_version']}"
    if a.get("entitlement_revision"):
        auth += f", entitlement revision {a['entitlement_revision']}"
    lines += ["", f"Authority observed: {auth}"]
    cl = expl["cleanup"]
    if cl:
        lines.append(
            "Cleanup: "
            + "; ".join(f"{c['context_id']}@{c['version']} {c['store_kind']}={c['state']}" for c in cl[:20])
        )
    else:
        lines.append("Cleanup: no purge rows for the objects involved")
    return "\n".join(lines)


@router.get("/decisions/{trace_id}", response_model=None)
def explain_decision(
    trace_id: Annotated[str, Path(min_length=1, max_length=128)],
    format: Literal["json", "text"] = Query(default="json"),
    session: Session = SessionDep,
    ident: Identity = ReadDep,
) -> Any:
    """Why was this decision made? Built from the audit record of the decision (``decision.authorize`` or
    ``release.authorize``, found by ``trace_id`` inside the caller's tenant ledger) and the live lineage graph.
    The audit record is the source of truth for the verdict; the dependency paths and cleanup state are read
    now, so they can have moved on since (see ``docs/lifecycle.md``)."""
    tenant = bind_tenant(ident)
    row = session.scalars(
        select(AuditLog)
        .where(
            AuditLog.tenant_id == tenant,
            AuditLog.action.in_(("decision.authorize", "release.authorize")),
            AuditLog.detail["trace_id"].as_string() == trace_id,
        )
        .order_by(AuditLog.seq.desc())
        .limit(1)
    ).first()
    if row is None:  # unknown, or another tenant's trace: indistinguishable
        raise HTTPException(404, detail={"error": "unknown_trace"})
    d = row.detail
    graph = GraphStore(session)
    objects = [_explain_object(session, graph, tenant, row, o) for o in d.get("objects", [])]
    involved: dict[Node, None] = {}
    for o in objects:
        for p in o["dependency_paths"]:
            for n in p:
                involved[(n["context_id"], n["object_version"])] = None
        if o["decision"] != "ALLOW" and o["version"] is not None:
            involved[(o["context_id"], o["version"])] = None
    cleanup: list[dict[str, Any]] = []
    cids = sorted({c for c, _ in involved})
    for i in range(0, len(cids), 400):
        for ob in session.scalars(
            select(InvalidationOutbox)
            .where(
                InvalidationOutbox.tenant_id == tenant, InvalidationOutbox.context_id.in_(cids[i : i + 400])
            )
            .order_by(InvalidationOutbox.id)
        ):
            if (ob.context_id, ob.version) in involved and len(cleanup) < MAX_CLEANUP_ROWS:
                cleanup.append(
                    {
                        "context_id": ob.context_id,
                        "version": ob.version,
                        "store_kind": ob.store_kind,
                        "state": ob.state,
                        "attempts": ob.attempts,
                        "last_error": ob.last_error,
                    }
                )
    policy_result = d.get("policy") or {}
    epoch_now = session.scalar(select(Tenant.revocation_epoch).where(Tenant.tenant_id == tenant)) or 0
    expl: dict[str, Any] = {
        "trace_id": trace_id,
        "kind": "release" if row.action == "release.authorize" else "authorize",
        "at": _iso(row.at),
        "decision": d.get("decision"),
        "reasons": d.get("reason", []),
        "principal": d.get("principal"),
        "purpose": d.get("purpose"),
        "objects": objects,
        "dependency_paths": [p for o in objects for p in o["dependency_paths"]],
        "causes": [c for o in objects for c in o["causes"]],
        "authority": {
            "revocation_epoch": d.get("revocation_epoch"),
            "current_revocation_epoch": int(epoch_now),
            "policy_version": d.get("policy_version"),
            "entitlement_revision": policy_result.get("entitlement_revision"),
            "policy_rule_id": policy_result.get("policy_rule_id"),
            "approval_id": policy_result.get("approval_id"),
        },
        "cleanup": cleanup,
    }
    expl["explanation"] = _render_text(expl)
    if format == "text":
        return PlainTextResponse(expl["explanation"] + "\n")
    return expl


class TransformationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transformation_id: Short
    version: str = Field(min_length=1, max_length=64)
    input_kinds: list[Annotated[str, StringConstraints(min_length=1, max_length=32)]] = Field(
        min_length=1, max_length=16
    )
    output_kind: str = Field(min_length=1, max_length=32)
    implementation_ref: str = Field(min_length=1, max_length=512)
    idempotent: bool = Field(strict=True)


class TransformationTag(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transformation_id: Short
    version: str = Field(min_length=1, max_length=64)


def _tr_view(row: Any) -> dict[str, Any]:
    return {
        "transformation_id": row.transformation_id,
        "version": row.version,
        "input_kinds": list(row.input_kinds),
        "output_kind": row.output_kind,
        "implementation_ref": row.implementation_ref,
        "idempotent": bool(row.idempotent),
        "created_by": row.created_by,
        "created_at": _iso(row.created_at),
    }


@router.post("/transformations", status_code=201)
def create_transformation(
    request: Request, body: TransformationCreate, session: Session = SessionDep, ident: Identity = AdminDep
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    try:
        row = register_transformation(
            session,
            tenant,
            body.transformation_id,
            body.version,
            body.input_kinds,
            body.output_kind,
            body.implementation_ref,
            body.idempotent,
            actor=ident.subject,
            at=request.app.state.clock(),
        )
        session.commit()
    except RebuildError as exc:
        session.rollback()
        raise HTTPException(409 if "already registered" in str(exc) else 422, detail=str(exc)[:300]) from exc
    except IntegrityError as exc:  # concurrent registration of the same (id, version)
        session.rollback()
        raise HTTPException(409, detail="transformation already registered") from exc
    except Exception:
        session.rollback()
        raise
    return _tr_view(row)


@router.get("/transformations")
def list_transformations_endpoint(session: Session = SessionDep, ident: Identity = ReadDep) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    return {"transformations": [_tr_view(r) for r in list_transformations(session, tenant)]}


@router.post("/derivations/{context_id}/{version}/transformation")
def tag_derivation_transformation(
    context_id: str,
    version: str,
    body: TransformationTag,
    session: Session = SessionDep,
    ident: Identity = IngestDep,
) -> dict[str, Any]:
    """Record which registered transformation produced an already-registered derivative (set-once; the
    envelope is not touched and nothing is re-signed). Lets the rebuild planner find it."""
    tenant = bind_tenant(ident)
    graph = GraphStore(session)
    if graph.get_object(tenant, context_id, version) is None:
        raise HTTPException(404, detail={"error": "unknown_context", "context_id": context_id})
    try:
        graph.tag_transformation(tenant, context_id, version, (body.transformation_id, body.version))
        audit_append(
            session,
            tenant,
            ident.subject,
            "derivation.tag_transformation",
            {
                "context_id": context_id[:255],
                "version": version[:255],
                "transformation_id": body.transformation_id,
                "transformation_version": body.version,
            },
        )
        session.commit()
    except DuplicateContext:
        session.rollback()
        raise
    except Exception:
        session.rollback()
        raise
    return {
        "context_id": context_id,
        "object_version": version,
        "transformation_id": body.transformation_id,
        "transformation_version": body.version,
    }


def _job_view(j: RebuildJobRow) -> dict[str, Any]:
    return {
        "job_id": j.id,
        "superseded": {"context_id": j.superseded_context_id, "object_version": j.superseded_version},
        "derivative": {"context_id": j.derivative_context_id, "object_version": j.derivative_version},
        "transformation": {"transformation_id": j.transformation_id, "version": j.transformation_version},
        "inputs": [{"context_id": c, "object_version": v} for c, v in j.inputs],
        "state": j.state,
        "attempts": j.attempts,
        "last_error": j.last_error,
        "result": (
            {"context_id": j.result_context_id, "object_version": j.result_version}
            if j.result_context_id is not None
            else None
        ),
        "created_by": j.created_by,
        "created_at": _iso(j.created_at),
    }


@router.get("/rebuilds")
def list_rebuilds(
    state: Literal["pending", "leased", "done", "failed"] | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    after_id: int = Query(default=0, ge=0),
    session: Session = SessionDep,
    ident: Identity = ReadDep,
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    return {
        "jobs": [
            _job_view(j) for j in list_jobs(session, tenant, state=state, limit=limit, after_id=after_id)
        ]
    }


@router.post("/rebuilds/run")
def run_rebuilds(request: Request, ident: Identity = AdminDep) -> dict[str, Any]:
    """Run the rebuild pass once, now, over the caller's tenant's due jobs (operators, drills, tests)."""
    tenant = bind_tenant(ident)
    state = request.app.state
    runner = RebuildRunner(state.session_factory, state.rebuild_handlers, tenant_id=tenant)
    r = runner.run_once(state.clock())
    return {
        "leased": r.leased,
        "done": r.done,
        "failed": r.failed,
        "retried": r.retried,
        "lost_lease": r.lost_lease,
    }


@router.post("/rebuilds/{context_id}/{version}")
def plan_and_enqueue_rebuild(
    request: Request, context_id: str, version: str, session: Session = SessionDep, ident: Identity = AdminDep
) -> dict[str, Any]:
    """Plan and enqueue rebuilds of the derivatives of a superseded object. Idempotent. ``planned: 0`` means
    the object has no successor yet or none of its direct derivatives carries a registered transformation."""
    tenant = bind_tenant(ident)
    try:
        jobs = enqueue_rebuild(
            session, tenant, context_id, version, actor=ident.subject, now=request.app.state.clock()
        )
        session.commit()
    except RebuildError as exc:
        session.rollback()
        raise HTTPException(404, detail={"error": "unknown_context", "context_id": context_id}) from exc
    except Exception:
        session.rollback()
        raise
    return {"planned": len(jobs), "jobs": [_job_view(j) for j in jobs]}


SessionId = Annotated[str, Path(min_length=1, max_length=255)]


class ExposureItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context_id: Short
    version: str | None = Field(default=None, max_length=255)


class ExposureReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str | None = None
    principal: Principal
    workload: Short | None = None
    exposures: list[ExposureItem] = Field(min_length=1, max_length=1000)


def _session_view(v: Any) -> dict[str, Any]:
    return {
        "session_id": v.session_id,
        "generation": v.generation,
        "needs_reset": v.needs_reset,
        "flag_reason": v.flag_reason,
        "flagged_at": _iso(v.flagged_at),
        "last_reset_at": _iso(v.last_reset_at),
        "expires_at": _iso(v.expires_at),
        "exposure_count": v.exposure_count,
    }


@router.post("/sessions/{session_id}/exposures")
def report_exposures(
    request: Request,
    session_id: SessionId,
    body: ExposureReport,
    session: Session = SessionDep,
    ident: Identity = ReadDep,
) -> dict[str, Any]:
    """SDKs/hosts report that ``session_id`` was served these objects (upsert; refreshes retention). Not
    audited per call (high volume); the revocation engine audits the flags it raises."""
    tenant = bind_tenant(ident, body.tenant_id)
    state = request.app.state
    now: datetime = state.clock()
    try:
        n = record_exposure(
            session,
            tenant,
            session_id,
            {"type": body.principal.type, "id": body.principal.id},
            body.workload,
            [(e.context_id, e.version) for e in body.exposures],
            now,
            retention=state.session_retention,
        )
        session.commit()
    except SessionError as exc:
        session.rollback()
        raise HTTPException(422, detail=str(exc)[:300]) from exc
    except IntegrityError as exc:  # concurrent first report of the same session
        session.rollback()
        raise HTTPException(409, detail="concurrent exposure report; retry") from exc
    except Exception:
        session.rollback()
        raise
    view = get_session_view(session, tenant, session_id, now)
    assert view is not None
    return {"recorded": n, **_session_view(view)}


@router.get("/sessions/{session_id}")
def get_session(
    request: Request, session_id: SessionId, session: Session = SessionDep, ident: Identity = ReadDep
) -> dict[str, Any]:
    tenant = bind_tenant(ident)
    view = get_session_view(session, tenant, session_id, request.app.state.clock())
    if view is None:  # unknown, expired or another tenant's session
        raise HTTPException(404, detail={"error": "unknown_session"})
    return _session_view(view)


@router.post("/sessions/{session_id}/reset")
def reset_session_endpoint(
    request: Request, session_id: SessionId, session: Session = SessionDep, ident: Identity = ReadDep
) -> dict[str, Any]:
    """Record that the host reset the session: bumps its generation and clears ``needs_reset``. ALES does not
    reset anything itself; what a reset means is host-defined."""
    tenant = bind_tenant(ident)
    try:
        view = reset_session(session, tenant, session_id, ident.subject, request.app.state.clock())
        session.commit()
    except SessionError as exc:
        session.rollback()
        raise HTTPException(404, detail={"error": "unknown_session"}) from exc
    except Exception:
        session.rollback()
        raise
    return _session_view(view)


__all__ = ["parse_duration", "router"]
