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

from .auth import Authenticator, make_auth_middleware
from .config import ConfigError, Settings, env_bool
from .middleware import BodySizeLimitMiddleware
from .routes import router
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
    )
    auth = Authenticator.from_env(e, tokens=tokens, allow_anonymous=allow_anonymous)
    key_material = snapshot_private_key if snapshot_private_key is not None else e.get("ALES_SNAPSHOT_KEY")
    if not key_material and settings.require_signatures and not env_bool(e, "ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY"):
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

    handlers: dict[str, Handler] = dict(outbox_handlers) if outbox_handlers is not None else {"*": log_only_handler}
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

    app = FastAPI(title="ALES INVARIANT control plane", version="0.2.0", lifespan=lifespan)
    app.state.engine = engine
    app.state.session_factory = factory
    app.state.settings = settings
    app.state.auth = auth
    app.state.snapshot_signer = signer
    app.state.outbox_worker = worker
    app.state.outbox_handlers = handlers

    def get_session() -> Iterator[Session]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.state.get_session = get_session
    app.include_router(router)

    # Added innermost-first: the body cap is outermost (runs before auth), auth wraps the routes.
    app.middleware("http")(make_auth_middleware(auth))
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
