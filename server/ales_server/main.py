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
    RebuildHandler,
    RebuildRunner,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session, sessionmaker

from .audit_export import AuditExporter
from .auth import Authenticator, make_auth_middleware
from .config import ConfigError, Settings, env_bool
from .governance import router as governance_router
from .hardening import (
    DENY_ONLY_WARNING,
    dev_unsafe_settings,
    is_memory_sqlite,
    make_engine,
    production_violations,
    purge_policy_issue,
)
from .identity import build_entitlements
from .lifecycle import parse_duration
from .lifecycle import router as lifecycle_router
from .metrics import Metrics
from .middleware import BodySizeLimitMiddleware
from .migrate import run_migrations_locked
from .providers import ProviderRunner
from .purge_config import build_purge_wiring
from .releases import router as releases_router
from .routes import router, wall_clock
from .snapshot import SnapshotSigner
from .worker import Handler, OutboxWorker, log_only_handler

DEFAULT_DATABASE_URL = "sqlite:///./invariant.db"
log = logging.getLogger("ales.server")


def _dev_banner(settings: Settings, auth: Authenticator, *, url: str, key_material: object) -> None:
    unsafe = dev_unsafe_settings(settings, auth, url=url, key_material=key_material)
    if unsafe:
        log.warning(
            "*** ALES DEVELOPMENT MODE: UNSAFE SETTINGS IN EFFECT *** %s. Set ALES_ENV=production to refuse to "
            "start with any of these.",
            "; ".join(unsafe),
        )


def _error(status: int, code: str, detail: object) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": code, "detail": detail})


def _install_exception_handlers(app: FastAPI) -> None:
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

    @app.exception_handler(RequestValidationError)
    async def _request_validation(_: Request, exc: RequestValidationError):
        # FastAPI's default handler echoes the offending input, which 500s on NaN/Infinity floats and on
        # non-UTF-8 bytes; never echo it.
        safe = [
            {"type": str(d.get("type")), "loc": [str(x) for x in d.get("loc", ())], "msg": str(d.get("msg"))}
            for d in exc.errors()
        ]
        return _error(422, "validation_error", safe)

    @app.exception_handler(ValidationError)
    async def _validation(_: Request, exc: ValidationError):
        return _error(
            422, "validation_error", exc.errors(include_url=False, include_context=False, include_input=False)
        )


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
    rebuild_handlers: Mapping[str, RebuildHandler] | None = None,
    env: Mapping[str, str] | None = None,
) -> FastAPI:
    """Build the app. Explicit arguments override the environment (``env`` defaults to ``os.environ``).

    ``tokens`` maps ``token -> {"tenant_id", "roles", "subject"}`` (tests); otherwise ``ALES_TOKENS`` /
    ``ALES_TOKENS_FILE`` are used. Invalid configuration raises :class:`ConfigError` (fail closed).

    ``rebuild_handlers`` maps ``transformation_id`` to a callable ``fn(inputs) -> RebuildOutput`` (see
    ``ales_core.rebuild``). None ship with ALES; a rebuild job whose transformation has no handler fails with a
    clear error. ``ALES_SESSION_RETENTION`` (default ``7d``) bounds how long reported session exposures live.
    """
    environment = os.environ if env is None else env
    url = database_url or environment.get("DATABASE_URL") or DEFAULT_DATABASE_URL
    settings = Settings.from_env(
        environment,
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
    session_retention = parse_duration(
        environment.get("ALES_SESSION_RETENTION")
    )  # ConfigError on a bad value
    authenticator = Authenticator.from_env(environment, tokens=tokens, allow_anonymous=allow_anonymous)
    key_material = (
        snapshot_private_key if snapshot_private_key is not None else environment.get("ALES_SNAPSHOT_KEY")
    )
    if settings.production:
        violations = production_violations(
            environment,
            settings,
            authenticator,
            url=url,
            allow_anonymous=allow_anonymous,
            key_material=key_material,
            handlers_supplied=outbox_handlers is not None,
        )
        if violations:
            raise ConfigError(
                "ALES_ENV=production refuses to start; "
                + str(len(violations))
                + " violation(s): "
                + "; ".join(f"({i}) {v}" for i, v in enumerate(violations, 1))
            )
        log.info("ALES_ENV=production: startup hardening checks passed")
    else:
        _dev_banner(settings, authenticator, url=url, key_material=key_material)
        issue = purge_policy_issue(environment, settings)
        if issue:
            raise ConfigError(issue)
    if (
        not settings.production
        and not key_material
        and settings.require_signatures
        and not env_bool(environment, "ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY")
    ):
        # An ephemeral per-process snapshot key breaks offline verification across replicas and
        # restarts; a signature-enforcing deployment must provision a persistent key explicitly.
        raise ConfigError(
            "ALES_REQUIRE_SIGNATURES=1 requires ALES_SNAPSHOT_KEY "
            "(or ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY=1 to accept a per-process key)"
        )
    signer = SnapshotSigner.load(
        key_material,
        key_id=environment.get("ALES_SNAPSHOT_KEY_ID") or None,
    )

    engine = make_engine(url)
    if env_bool(environment, "ALES_SKIP_STARTUP_MIGRATIONS"):
        log.info("startup migrations skipped (ALES_SKIP_STARTUP_MIGRATIONS); readyz still checks revision")
    else:
        run_migrations_locked(engine)  # alembic is the only schema path (works for in-memory SQLite too)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    handlers: dict[str, Handler]
    if outbox_handlers is not None:
        handlers = dict(outbox_handlers)
    else:
        wiring = build_purge_wiring(environment)  # ConfigError on a bad ALES_PURGE_TARGETS (fail closed)
        if settings.purge_policy == "deny-only":
            handlers = {"*": log_only_handler}
            log.warning(DENY_ONLY_WARNING)
        elif wiring is not None:
            handlers = wiring.registry.as_outbox_handlers()
            log.info("purge targets wired from ALES_PURGE_TARGETS: %s", ",".join(wiring.target_names()))
        else:
            handlers = {"*": log_only_handler}
            log.warning(
                "ALES_PURGE_TARGETS is not set: purge is LOG-ONLY and revoked bytes REMAIN in every downstream "
                "store (vector index, cache, ...). Development default; production refuses to start like this "
                "unless ALES_PURGE_POLICY=deny-only."
            )
    rebuild_map: dict[str, RebuildHandler] = dict(rebuild_handlers or {})
    worker: OutboxWorker | None = None
    if settings.outbox_interval > 0:
        if is_memory_sqlite(url):
            # a single shared connection cannot be used from two threads at once
            log.warning("outbox worker disabled: in-memory SQLite supports a single connection only")
        else:
            worker = OutboxWorker(
                session_factory,
                handlers,
                settings.outbox_interval,
                rebuild_runner=RebuildRunner(session_factory, rebuild_map),
            )

    policy_runner = (
        ProviderRunner(settings.policy_providers, env=environment) if settings.policy_providers else None
    )
    if policy_runner is not None:
        log.info(
            "external policy providers: %s",
            ", ".join(
                f"{c.name}({c.kind.value},{'required' if c.required else 'optional'})"
                for c in policy_runner.configs
            ),
        )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if worker is not None:
            worker.start()
        try:
            yield
        finally:
            if worker is not None:
                worker.stop()
            if policy_runner is not None:
                policy_runner.close()

    app = FastAPI(title="ALES INVARIANT control plane", version="0.3.0", lifespan=lifespan)
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.settings = settings
    app.state.auth = authenticator
    app.state.snapshot_signer = signer
    app.state.outbox_worker = worker
    app.state.policy_runner = policy_runner
    app.state.entitlements, app.state.entitlements_static = build_entitlements(
        environment, authenticator.oidc, required_default=settings.entitlements_required
    )
    app.state.outbox_handlers = handlers
    app.state.rebuild_handlers = rebuild_map
    app.state.session_retention = session_retention
    app.state.metrics = Metrics()
    authenticator.metrics = app.state.metrics
    export_path = (environment.get("ALES_AUDIT_EXPORT_FILE") or "").strip()
    app.state.audit_exporter = None
    if export_path:
        exporter = AuditExporter(export_path, app.state.metrics)
        exporter.attach(session_factory)
        app.state.audit_exporter = exporter
    metrics_public = env_bool(
        environment, "ALES_METRICS_PUBLIC"
    )  # default OFF: /v1/metrics needs a read token
    app.state.metrics_public = metrics_public
    #: injectable wall clock (tests); every decision-path timestamp comes from here
    app.state.clock = wall_clock

    def get_session() -> Iterator[Session]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.state.get_session = get_session
    app.include_router(router)
    app.include_router(governance_router)
    app.include_router(releases_router)
    app.include_router(lifecycle_router)

    # Added innermost-first: the body cap is outermost (runs before auth), auth wraps the routes.
    app.middleware("http")(
        make_auth_middleware(authenticator, frozenset({"/v1/metrics"}) if metrics_public else frozenset())
    )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body)

    _install_exception_handlers(app)

    return app


_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    """Lazy module-level ``app`` (``uvicorn ales_server.main:app``): importing the package, e.g. for
    ``python -m ales_server.preflight``, must not itself start (and possibly refuse) a production server."""
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)


__all__ = ["ConfigError", "app", "create_app"]  # noqa: F822  (``app`` is provided lazily by __getattr__)
