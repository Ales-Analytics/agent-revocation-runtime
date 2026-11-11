"""FastAPI app factory for the ALES INVARIANT control plane."""

from __future__ import annotations

import os
from collections.abc import Iterator

from ales_core import (
    AuthorityWidening,
    DuplicateContext,
    InvalidEnvelope,
    LineageIncomplete,
    create_all,
)
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .routes import router

DEFAULT_DATABASE_URL = "sqlite:///./invariant.db"


def _make_engine(database_url: str):
    url = make_url(database_url)
    if url.get_backend_name() == "sqlite":
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if url.database in (None, "", ":memory:"):
            kwargs["poolclass"] = StaticPool  # one shared connection so the memory DB persists
        return create_engine(database_url, **kwargs)
    return create_engine(database_url, pool_pre_ping=True)


def _error(status: int, code: str, detail: object) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": code, "detail": detail})


def create_app(database_url: str | None = None) -> FastAPI:
    url = database_url or os.environ.get("DATABASE_URL") or DEFAULT_DATABASE_URL
    engine = _make_engine(url)
    create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    app = FastAPI(title="ALES INVARIANT control plane", version="0.1.0")
    app.state.engine = engine
    app.state.session_factory = factory

    def get_session() -> Iterator[Session]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.state.get_session = get_session
    app.include_router(router)

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

    @app.exception_handler(ValidationError)
    async def _validation(_: Request, exc: ValidationError):
        return _error(422, "validation_error", exc.errors(include_url=False, include_context=False, include_input=False))

    return app


app = create_app()
