"""Issuer-qualified principals and group entries in principal scopes (v0.5)."""

from __future__ import annotations

import uuid

import pytest
from ales_core import (
    AuthorizeRequest,
    Decision,
    ObjectRef,
    Principal,
    ReasonCode,
    RevocationEngine,
    RevocationEvent,
    authorize,
)
from ales_core.resolver import principal_in_scope, qualified_principal
from core_fixtures import NOW, TENANT, make_env
from pydantic import ValidationError


def _req(cid, pid="alice", issuer=None, groups=None, purpose="qa"):
    return AuthorizeRequest(
        tenant_id=TENANT,
        principal=Principal(type="user", id=pid, issuer=issuer),
        purpose=purpose,
        objects=[ObjectRef(context_id=cid)],
        groups=groups or [],
    )


def _source(graph, session, principals):
    env = make_env("source", principals=principals)
    graph.register_source(env)
    session.commit()
    return env.context_id


def test_issuer_qualified_scope_isolates_two_alices(graph, session):
    cid = _source(graph, session, [qualified_principal("https://idp-a/", "alice")])
    assert authorize(session, _req(cid, issuer="https://idp-a/"), NOW).decision == Decision.ALLOW
    other = authorize(session, _req(cid, issuer="https://idp-b/"), NOW)
    assert other.decision == Decision.DENY and other.reason == [ReasonCode.PRINCIPAL_NOT_IN_SCOPE]
    # a request with no issuer cannot claim the qualified entry either
    assert authorize(session, _req(cid), NOW).decision == Decision.DENY


def test_bare_scope_still_matches_either_issuer_compat(graph, session):
    cid = _source(graph, session, ["alice"])
    for issuer in (None, "https://idp-a/", "https://idp-b/"):
        assert authorize(session, _req(cid, issuer=issuer), NOW).decision == Decision.ALLOW


def test_group_entry_matches_resolved_group_only(graph, session):
    cid = _source(graph, session, ["group:eng"])
    assert authorize(session, _req(cid), NOW).decision == Decision.DENY
    assert authorize(session, _req(cid, groups=["sales"]), NOW).decision == Decision.DENY
    assert authorize(session, _req(cid, groups=["sales", "eng"]), NOW).decision == Decision.ALLOW


def test_group_name_does_not_collide_with_principal_id(graph, session):
    cid = _source(graph, session, ["bob"])
    assert authorize(session, _req(cid, groups=["bob"]), NOW).decision == Decision.DENY


def test_reserved_prefix_ids_cannot_impersonate(graph, session):
    cid = _source(graph, session, ["group:eng", "iss:i:alice"])
    assert authorize(session, _req(cid, pid="group:eng"), NOW).decision == Decision.DENY
    assert authorize(session, _req(cid, pid="iss:i:alice"), NOW).decision == Decision.DENY


def test_groups_never_match_empty_scope(graph, session):
    cid = _source(graph, session, [])
    assert authorize(session, _req(cid, groups=["eng", "x"]), NOW).decision == Decision.DENY
    assert principal_in_scope(frozenset(), "alice", "i", ["eng"]) is False


def test_mixed_spelling_parents_intersect_to_nobody(graph, session):
    a = make_env("source", principals=["group:eng"])
    b = make_env("source", principals=["alice"])
    graph.register_source(a)
    graph.register_source(b)
    d = make_env("summary", [(a.context_id, "v1"), (b.context_id, "v1")], principals=[])
    graph.register_derivation(d)
    session.commit()
    assert authorize(session, _req(d.context_id, groups=["eng"]), NOW).decision == Decision.DENY


def test_scoped_revocation_by_group_and_issuer_applies(graph, session, chain):
    src = chain["source"]
    RevocationEngine().accept(
        session,
        RevocationEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=TENANT,
            source_id=src.context_id,
            reason="acl_changed",
            effective_at=NOW,
            actor="admin",
            affected_scope={"principals": ["group:eng", qualified_principal("idp-a", "carol")]},
        ),
        actor="admin",
    )
    session.commit()
    mem = chain["memory"].context_id
    assert authorize(session, _req(mem), NOW).decision == Decision.ALLOW
    assert authorize(session, _req(mem, groups=["eng"]), NOW).decision == Decision.DENY
    assert authorize(session, _req(mem, pid="carol", issuer="idp-a"), NOW).decision == Decision.DENY
    assert authorize(session, _req(mem, pid="carol", issuer="idp-b"), NOW).decision == Decision.ALLOW


def test_models_validate_groups_and_issuer():
    with pytest.raises(ValidationError):
        Principal(type="user", id="a", issuer="")
    with pytest.raises(ValidationError):
        _req("c", groups=[""])
    assert _req("c").groups == [] and _req("c").principal.issuer is None
