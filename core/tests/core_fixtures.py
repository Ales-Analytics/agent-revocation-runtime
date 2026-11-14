from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from ales_core import (
    AuthorizeRequest,
    ContextEnvelope,
    GraphStore,
    ObjectRef,
    ParentRef,
    Principal,
    create_all,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

NOW = datetime(2026, 1, 1, tzinfo=UTC)
TENANT = "tenant-a"


@pytest.fixture
def engine():
    eng = create_engine("sqlite:///:memory:", poolclass=StaticPool, connect_args={"check_same_thread": False})
    create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


@pytest.fixture
def graph(session):
    return GraphStore(session)


def digest(seed: str = "x") -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def make_env(
    kind: str = "source",
    parents: list[tuple[str, str]] | None = None,
    *,
    tenant: str = TENANT,
    context_id: str | None = None,
    version: str = "v1",
    classification: str = "internal",
    trust: str = "verified",
    principals: list[str] | None = None,
    purposes: list[str] | None = None,
    expires_at: datetime | None = None,
    valid_from: datetime | None = None,
    successor_of: tuple[str, str] | None = None,
) -> ContextEnvelope:
    cid = context_id or str(uuid.uuid4())
    return ContextEnvelope(
        context_id=cid,
        tenant_id=tenant,
        object_id=f"obj-{cid[:8]}",
        object_version=version,
        content_digest=digest(cid + version),
        kind=kind,
        source_system="test",
        principal_scope=principals,
        purpose_scope=purposes,
        classification=classification,
        trust_state=trust,
        parent_refs=[ParentRef(context_id=c, object_version=v) for c, v in (parents or [])],
        policy_version="p0",
        valid_from=valid_from or NOW - timedelta(days=30),
        expires_at=expires_at,
        successor_of=({"context_id": successor_of[0], "object_version": successor_of[1]} if successor_of else None),
    )


def req(*objects, tenant: str = TENANT, principal: str = "alice", purpose: str = "qa") -> AuthorizeRequest:
    refs = []
    for o in objects:
        if isinstance(o, tuple):
            refs.append(ObjectRef(context_id=o[0], version=o[1]))
        else:
            refs.append(ObjectRef(context_id=o))
    return AuthorizeRequest(
        tenant_id=tenant, principal=Principal(type="user", id=principal), purpose=purpose, objects=refs
    )


@pytest.fixture
def chain(graph, session):
    """source -> chunk -> summary -> memory (all tenant-a, v1). Returns dict of envelopes."""
    src = make_env("source")
    chunk = make_env("chunk", [(src.context_id, "v1")])
    summ = make_env("summary", [(chunk.context_id, "v1")])
    mem = make_env("memory", [(summ.context_id, "v1")])
    graph.register_source(src)
    for e in (chunk, summ, mem):
        graph.register_derivation(e)
    session.commit()
    return {"source": src, "chunk": chunk, "summary": summ, "memory": mem}
