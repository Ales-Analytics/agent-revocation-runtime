"""FastAPI app factory for the ALES INVARIANT control plane."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator, Mapping
from contextlib import asynccontextmanager
from typing import Any

from ales_core import (
    AuthorityWidening,
    DuplicateContext,
    InvalidDetail,
    InvalidEnvelope,
    LineageIncomplete,
)
from ales_core.migrations import run_migrations
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .audit_export import AuditExporter
from .auth import Authenticator, make_auth_middleware
from .config import ConfigError, Settings, env_bool
from .governance import router as governance_router
from .metrics import Metrics
from .middleware import BodySizeLimitMiddleware
from .purge_config import build_purge_wiring
from .routes import router, wall_clock
from .snapshot import SnapshotSigner
from .worker import Handler, OutboxWorker, log_only_handler

DEFAULT_DATABASE_URL = "sqlite:///./invariant.db"
log = logging.getLogger("ales.server")


def _make_engine(database_url: str):
    url = make_url(database_url)
    if url.get_backend_name() == "sqlite":
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if url.database in (None, "", ":memory:"):
            kwargs["poolclass"] = StaticPool  # one shared connection so the memory DB persists
        return create_engine(database_url, **kwargs)
    return create_engine(database_url, pool_pre_ping=True)


def _is_memory_sqlite(database_url: str) -> bool:
    url = make_url(database_url)
    return url.get_backend_name() == "sqlite" and url.database in (None, "", ":memory:")


def _is_sqlite(database_url: str) -> bool:
    return make_url(database_url).get_backend_name() == "sqlite"


def _production_violations(
    e: Mapping[str, str],
    settings: Settings,
    auth: Authenticator,
    *,
    url: str,
    allow_anonymous: bool | None,
    key_material: object,
) -> list[str]:
    """Every reason a production (``ALES_ENV=production``) process must refuse to start, all at once."""
    bad: list[str] = []
    if (auth.registry is None or len(auth.registry) == 0) and auth.oidc is None:
        bad.append("no authentication configured: set ALES_TOKENS / ALES_TOKENS_FILE and/or ALES_OIDC_CONFIG")
    if e.get("ALES_DEV_ALLOW_ANONYMOUS") is not None or allow_anonymous:
        bad.append("ALES_DEV_ALLOW_ANONYMOUS must not be set at all in production")
    if not settings.require_signatures:
        if env_bool(e, "ALES_ALLOW_UNSIGNED_INGRESS"):
            log.warning(
                "ALES_ALLOW_UNSIGNED_INGRESS=1: production is accepting UNSIGNED envelopes and revocations "
                "(ALES_REQUIRE_SIGNATURES is off). Explicit operator override."
            )
        else:
            bad.append("ALES_REQUIRE_SIGNATURES must be on (or set ALES_ALLOW_UNSIGNED_INGRESS=1 to accept unsigned ingress)")
    if not key_material:
        if env_bool(e, "ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY"):
            log.warning(
                "ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY=1: production signs snapshots with a per-process key; offline "
                "verification will break across restarts and replicas."
            )
        else:
            bad.append("ALES_SNAPSHOT_KEY is required (or set ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY=1 to accept a per-process key)")
    if _is_sqlite(url):
        if env_bool(e, "ALES_ALLOW_SQLITE"):
            log.warning(
                "ALES_ALLOW_SQLITE=1: production is running on SQLite. Single node only, no horizontal scale-out, "
                "no row locking. Explicit operator override."
            )
        else:
            bad.append("DATABASE_URL is SQLite: use Postgres (or set ALES_ALLOW_SQLITE=1 to accept a single-node SQLite)")
    if settings.enforce_workloads == "off":
        bad.append("ALES_ENFORCE_WORKLOADS=off is not allowed in production (use 'strict' or 'auto')")
    return bad


def _dev_banner(
    settings: Settings, auth: Authenticator, *, url: str, key_material: object
) -> None:
    unsafe: list[str] = []
    if auth.allow_anonymous:
        unsafe.append("anonymous authentication (every caller has ALL roles and picks its tenant)")
    if not key_material:
        unsafe.append("ephemeral snapshot key (per-process; offline verification breaks across restarts/replicas)")
    if not settings.require_signatures:
        unsafe.append("signature ingress OFF (unsigned envelopes and revocations are accepted)")
    if _is_sqlite(url):
        unsafe.append("SQLite database (single node, not for production)")
    if settings.enforce_workloads == "off":
        unsafe.append("workload/grant enforcement OFF (agent_id is an unverified label)")
    if settings.approval_allow_self:
        unsafe.append("approval separation of duties DISABLED")
    if unsafe:
        log.warning(
            "*** ALES DEVELOPMENT MODE: UNSAFE SETTINGS IN EFFECT *** %s. Set ALES_ENV=production to refuse to "
            "start with any of these.",
            "; ".join(unsafe),
        )


def _error(status: int, code: str, detail: object) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": code, "detail": detail})


def create_app(
    database_url: str | None = None,
    tokens: Mapping[str, Mapping[str, Any]] | None = None,
    require_signatures: bool | None = None,
    snapshot_private_key: str | bytes | Ed25519PrivateKey | None = None,
    *,
    allow_anonymous: bool | None = None,
    max_body: int | None = None,
    snapshot_lease: int | None = None,
    outbox_interval: float | None = None,
    enforce_workloads: str | None = None,
    approval_allow_self: bool | None = None,
    require_grants: bool | None = None,
    outbox_handlers: Mapping[str, Handler] | None = None,
    env: Mapping[str, str] | None = None,
) -> FastAPI:
    """Build the app. Explicit arguments override the environment (``env`` defaults to ``os.environ``).

    ``tokens`` maps ``token -> {"tenant_id", "roles", "subject"}`` (tests); otherwise ``ALES_TOKENS`` /
    ``ALES_TOKENS_FILE`` are used. Invalid configuration raises :class:`ConfigError` (fail closed).
    """
    e = os.environ if env is None else env
    url = database_url or e.get("DATABASE_URL") or DEFAULT_DATABASE_URL
    settings = Settings.from_env(
        e,
        require_signatures=require_signatures,
        max_body=max_body,
        snapshot_lease=snapshot_lease,
        outbox_interval=outbox_interval,
        enforce_workloads=enforce_workloads,
        approval_allow_self=approval_allow_self,
        require_grants=require_grants,
    )
    if settings.enforce_workloads == "off":
        log.warning(
            "ALES_ENFORCE_WORKLOADS=off: workload identity, capability and grant checks are DISABLED; "
            "agent_id is an unverified label. Use 'strict' in production."
        )
    if settings.approval_allow_self:
        log.warning("ALES_APPROVAL_ALLOW_SELF=1: separation of duties on approvals is DISABLED (dev only)")
    auth = Authenticator.from_env(e, tokens=tokens, allow_anonymous=allow_anonymous)
    key_material = snapshot_private_key if snapshot_private_key is not None else e.get("ALES_SNAPSHOT_KEY")
    if settings.production:
        violations = _production_violations(
            e, settings, auth, url=url, allow_anonymous=allow_anonymous, key_material=key_material
        )
        if violations:
            raise ConfigError(
                "ALES_ENV=production refuses to start; " + str(len(violations)) + " violation(s): "
                + "; ".join(f"({i}) {v}" for i, v in enumerate(violations, 1))
            )
        log.info("ALES_ENV=production: startup hardening checks passed")
    else:
        _dev_banner(settings, auth, url=url, key_material=key_material)
    if (
        not settings.production
        and not key_material
        and settings.require_signatures
        and not env_bool(e, "ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY")
    ):
        # An ephemeral per-process snapshot key breaks offline verification across replicas and
        # restarts; a signature-enforcing deployment must provision a persistent key explicitly.
        raise ConfigError(
            "ALES_REQUIRE_SIGNATURES=1 requires ALES_SNAPSHOT_KEY "
            "(or ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY=1 to accept a per-process key)"
        )
    signer = SnapshotSigner.load(
        key_material,
        key_id=e.get("ALES_SNAPSHOT_KEY_ID") or None,
    )

    engine = _make_engine(url)
    if env_bool(e, "ALES_SKIP_STARTUP_MIGRATIONS"):
        log.info("startup migrations skipped (ALES_SKIP_STARTUP_MIGRATIONS); readyz still checks revision")
    else:
        run_migrations(engine)  # alembic is the only schema path (works for in-memory SQLite too)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    handlers: dict[str, Handler]
    if outbox_handlers is not None:
        handlers = dict(outbox_handlers)
    else:
        wiring = build_purge_wiring(e)  # ConfigError on a bad ALES_PURGE_TARGETS (fail closed)
        if wiring is not None:
            handlers = wiring.registry.as_outbox_handlers()
            log.info("purge targets wired from ALES_PURGE_TARGETS: %s", ",".join(wiring.target_names()))
        else:
            handlers = {"*": log_only_handler}
            if settings.production:
                log.error(
                    "ALES_ENV=production but ALES_PURGE_TARGETS is not set: purge is LOG-ONLY and revoked "
                    "bytes REMAIN in every downstream store (vector index, cache, ...). Safety of decisions is "
                    "unaffected (tombstones); physical erasure is not happening. Configure ALES_PURGE_TARGETS."
                )
    worker: OutboxWorker | None = None
    if settings.outbox_interval > 0:
        if _is_memory_sqlite(url):
            # a single shared connection cannot be used from two threads at once
            log.warning("outbox worker disabled: in-memory SQLite supports a single connection only")
        else:
            worker = OutboxWorker(factory, handlers, settings.outbox_interval)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if worker is not None:
            worker.start()
        try:
            yield
        finally:
            if worker is not None:
                worker.stop()

    app = FastAPI(title="ALES INVARIANT control plane", version="0.3.0", lifespan=lifespan)
    app.state.engine = engine
    app.state.session_factory = factory
    app.state.settings = settings
    app.state.auth = auth
    app.state.snapshot_signer = signer
    app.state.outbox_worker = worker
    app.state.outbox_handlers = handlers
    app.state.metrics = Metrics()
    auth.metrics = app.state.metrics
    export_path = (e.get("ALES_AUDIT_EXPORT_FILE") or "").strip()
    app.state.audit_exporter = None
    if export_path:
        exporter = AuditExporter(export_path, app.state.metrics)
        exporter.attach(factory)
        app.state.audit_exporter = exporter
    metrics_public = env_bool(e, "ALES_METRICS_PUBLIC")  # default OFF: /v1/metrics needs a read token
    app.state.metrics_public = metrics_public
    #: injectable wall clock (tests); every decision-path timestamp comes from here
    app.state.clock = wall_clock

    def get_session() -> Iterator[Session]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.state.get_session = get_session
    app.include_router(router)
    app.include_router(governance_router)

    # Added innermost-first: the body cap is outermost (runs before auth), auth wraps the routes.
    app.middleware("http")(make_auth_middleware(auth, frozenset({"/v1/metrics"}) if metrics_public else frozenset()))
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body)

    @app.exception_handler(LineageIncomplete)
    async def _lineage(_: Request, exc: LineageIncomplete):
        missing = [{"context_id": c, "object_version": v} for c, v in exc.missing]
        return _error(422, "lineage_incomplete", missing)

    @app.exception_handler(DuplicateContext)
    async def _dup(_: Request, exc: DuplicateContext):
        return _error(409, "duplicate_context", str(exc))

    @app.exception_handler(AuthorityWidening)
    async def _widen(_: Request, exc: AuthorityWidening):
        return _error(409, "authority_widening", str(exc))

    @app.exception_handler(InvalidEnvelope)
    async def _invalid(_: Request, exc: InvalidEnvelope):
        return _error(422, "invalid_envelope", str(exc))

    @app.exception_handler(InvalidDetail)
    async def _invalid_detail(_: Request, exc: InvalidDetail):
        return _error(422, "invalid_detail", str(exc))

    @app.exception_handler(ValidationError)
    async def _validation(_: Request, exc: ValidationError):
        return _error(422, "validation_error", exc.errors(include_url=False, include_context=False, include_input=False))

    return app


app = create_app()

__all__ = ["ConfigError", "app", "create_app"]
