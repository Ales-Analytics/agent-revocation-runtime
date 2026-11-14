"""v0.4 core correctness ledger: valid_from, scope semantics, validity bounds, registration immutability,
successor_of, graph integrity, issuer-key compromise workflow, migration 0004."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from ales_core import (
    ApprovalStore,
    AuthorityWidening,
    ContextEnvelope,
    ContextObject,
    Decision,
    DerivationEdge,
    DuplicateContext,
    KeyRegistry,
    PolicyDocument,
    PolicyStore,
    ReasonCode,
    RevocationEngine,
    RevocationEvent,
    RevocationEventRow,
    authorize,
    authorize_ex,
    find_successors,
    verify_graph,
)
from ales_core.keys import affected_sources, compromise_event_id, revoke_sources_for_key
from ales_core.migrations import downgrade_migrations, run_migrations
from core_fixtures import NOW, TENANT, make_env, req
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, delete, select, text

ENG = RevocationEngine()
FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


def ev(source_id, reason="acl_changed", version=None, at=None, event_id=None):
    return RevocationEvent(
        event_id=event_id or str(uuid.uuid4()), tenant_id=TENANT, source_id=source_id,
        source_version=version, reason=reason, effective_at=at or NOW,
    )


# ------------------------------------------------------------------ 1. valid_from
def test_not_yet_valid_object_is_denied_then_allowed(graph, session):
    s = make_env("source", valid_from=NOW + timedelta(hours=1))
    graph.register_source(s)
    session.commit()
    r = authorize(session, req(s.context_id), NOW)
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.NOT_YET_VALID]
    assert authorize(session, req(s.context_id), NOW + timedelta(hours=1)).decision == Decision.ALLOW


def test_not_yet_valid_ancestor_denies_descendant(graph, session):
    s = make_env("source", valid_from=NOW + timedelta(hours=1))
    c = make_env("chunk", [(s.context_id, "v1")])  # child itself is valid; its ancestor is not
    graph.register_source(s)
    graph.register_derivation(c)
    session.commit()
    r = authorize(session, req(c.context_id), NOW)
    assert r.decision == Decision.DENY and ReasonCode.NOT_YET_VALID in r.reason
    assert authorize(session, req(c.context_id), NOW + timedelta(hours=2)).decision == Decision.ALLOW


def test_unversioned_ref_skips_scheduled_future_version(graph, session):
    cid = str(uuid.uuid4())
    graph.register_source(make_env("source", context_id=cid, version="v1"))
    graph.register_source(make_env("source", context_id=cid, version="v2", valid_from=NOW + timedelta(days=1)))
    session.commit()
    r = authorize(session, req(cid), NOW)
    assert r.decision == Decision.ALLOW and r.objects[0].version == "v1"
    assert authorize(session, req(cid), NOW + timedelta(days=2)).objects[0].version == "v2"


# ------------------------------------------------------------------ 2. scope semantics
def test_envelope_accepts_empty_scope_and_distinguishes_null():
    assert make_env("source", principals=[]).principal_scope == []
    assert make_env("source").principal_scope is None
    dumped = make_env("source", principals=[]).model_dump(mode="json")
    assert dumped["principal_scope"] == [] and dumped["purpose_scope"] is None


def test_empty_scope_source_denies_everyone(graph, session):
    s = make_env("source", principals=[])
    graph.register_source(s)
    session.commit()
    r = authorize(session, req(s.context_id, principal="alice"), NOW)
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.PRINCIPAL_NOT_IN_SCOPE]


def test_scope_null_vs_empty_round_trips_through_db(graph, session):
    a = make_env("source", principals=[], purposes=["qa"])
    b = make_env("source")
    graph.register_source(a)
    graph.register_source(b)
    session.commit()
    session.expire_all()
    ra, rb = session.get(ContextObject, (a.context_id, "v1")), session.get(ContextObject, (b.context_id, "v1"))
    assert ra.principal_scope == [] and ra.purpose_scope == ["qa"]
    assert rb.principal_scope is None and rb.purpose_scope is None


def test_disjoint_parents_register_and_deny_everyone(graph, session):
    p1 = make_env("source", principals=["alice"])
    p2 = make_env("source", principals=["bob"])
    graph.register_source(p1)
    graph.register_source(p2)
    kid = make_env("summary", [(p1.context_id, "v1"), (p2.context_id, "v1")], principals=[])
    row = graph.register_derivation(kid)  # previously AuthorityWidening
    session.commit()
    assert row.principal_scope == []
    for who in ("alice", "bob", "carol"):
        r = authorize(session, req(kid.context_id, principal=who), NOW)
        assert r.decision == Decision.DENY and ReasonCode.PRINCIPAL_NOT_IN_SCOPE in r.reason


def test_genuine_widening_still_refused(graph):
    p1 = make_env("source", principals=["alice"])
    p2 = make_env("source", principals=["bob"])
    graph.register_source(p1)
    graph.register_source(p2)
    parents = [(p1.context_id, "v1"), (p2.context_id, "v1")]
    with pytest.raises(AuthorityWidening):
        graph.register_derivation(make_env("summary", parents, principals=["alice"]))
    with pytest.raises(AuthorityWidening):
        graph.register_derivation(make_env("summary", parents))  # null claim under empty intersection
    e = make_env("source", principals=[])
    graph.register_source(e)
    with pytest.raises(AuthorityWidening):
        graph.register_derivation(make_env("chunk", [(e.context_id, "v1")]))  # unrestricted under nobody


# ------------------------------------------------------------------ 3. validity bound completeness
def test_valid_until_is_earliest_ancestor_expiry_and_cutover(graph, session):
    s = make_env("source", expires_at=NOW + timedelta(minutes=10))
    c = make_env("chunk", [(s.context_id, "v1")], expires_at=NOW + timedelta(minutes=5))
    m = make_env("memory", [(c.context_id, "v1")], expires_at=NOW + timedelta(minutes=5))
    graph.register_source(s)
    graph.register_derivation(c)
    graph.register_derivation(m)
    session.commit()
    r = authorize(session, req(m.context_id), NOW)
    assert r.decision == Decision.ALLOW
    until = (NOW + timedelta(minutes=5)).strftime(FMT)
    assert r.valid_until == until and r.objects[0].valid_until == until
    # a cached ALLOW is only reusable strictly before valid_until; at the boundary the verdict flips
    assert authorize(session, req(m.context_id), NOW + timedelta(minutes=5)).decision == Decision.DENY
    assert authorize(session, req(m.context_id), NOW + timedelta(minutes=5, microseconds=-1)).decision == Decision.ALLOW


def test_valid_until_takes_min_of_expiry_and_pending_tombstone(graph, session, chain):
    src = chain["source"].context_id
    ENG.accept(session, ev(src, at=NOW + timedelta(minutes=3)), now=NOW)
    # ancestor expiry later than the tombstone: tombstone wins
    row = session.get(ContextObject, (src, "v1"))
    row.expires_at = NOW + timedelta(minutes=9)
    session.commit()
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.valid_until == (NOW + timedelta(minutes=3)).strftime(FMT)
    row.expires_at = NOW + timedelta(minutes=2)
    session.commit()
    assert authorize(session, req(chain["memory"].context_id), NOW).valid_until == (
        NOW + timedelta(minutes=2)
    ).strftime(FMT)


def test_no_bound_means_no_valid_until(session, chain):
    assert authorize(session, req(chain["memory"].context_id), NOW).valid_until is None


def _install_hr(session):
    PolicyStore.install(
        session,
        PolicyDocument.model_validate(
            {"policy_id": "pol", "tenant_id": TENANT, "version": 1, "default_action": "allow",
             "created_by": "admin",
             "rules": [{"rule_id": "hr", "effect": "human_review", "subjects": {"principals": ["alice"]}}]}
        ),
    )
    PolicyStore.activate(session, TENANT, "pol", 1, actor="admin")
    session.commit()


def test_honoured_approval_bounds_valid_until_and_cutover(session, chain):
    _install_hr(session)
    r = req(chain["memory"].context_id)
    out = authorize_ex(session, r, NOW)
    ap = ApprovalStore.ensure_pending(session, TENANT, out.fingerprint, out.approval_context, now=NOW)
    ApprovalStore.decide(session, TENANT, ap.approval_id, True, "boss", 300, now=NOW)
    session.commit()
    ok = authorize_ex(session, r, NOW + timedelta(seconds=10))
    assert ok.response.decision == Decision.ALLOW and ok.approval_id == ap.approval_id
    cut = (NOW + timedelta(seconds=300)).strftime(FMT)
    assert ok.response.valid_until == cut and ok.response.objects[0].valid_until == cut
    # at the boundary the approval has lapsed: the cached ALLOW must not survive
    assert authorize(session, r, NOW + timedelta(seconds=300)).decision == Decision.HUMAN_REVIEW


# ------------------------------------------------------------------ 4. registration immutability
def _src(graph, **kw):
    e = make_env("source", **kw)
    graph.register_source(e)
    return e


def test_identical_reregistration_is_noop(graph, session):
    e = _src(graph, principals=["b", "a"], expires_at=NOW + timedelta(days=1))
    again = e.model_copy(update={"principal_scope": ["a", "b"]})  # order-insensitive
    assert graph.register_source(again).context_id == e.context_id
    session.commit()
    assert len(session.scalars(select(ContextObject)).all()) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"classification": "restricted"},
        {"trust_state": "untrusted"},
        {"principal_scope": ["x"]},
        {"principal_scope": []},  # null -> [] is a semantic change
        {"purpose_scope": ["x"]},
        {"expires_at": NOW + timedelta(days=9)},
        {"valid_from": NOW},
        {"content_digest": "sha256:" + "0" * 64},
        {"successor_of": {"context_id": str(uuid.uuid4()), "object_version": "v1"}},
    ],
)
def test_reregistration_with_any_semantic_change_conflicts(graph, change):
    e = _src(graph)
    data = e.model_dump(mode="json") | {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in change.items()}
    with pytest.raises(DuplicateContext):
        graph.register_source(ContextEnvelope.model_validate(data))


def test_empty_to_null_scope_conflicts(graph):
    e = _src(graph, principals=[])
    with pytest.raises(DuplicateContext):
        graph.register_source(e.model_copy(update={"principal_scope": None}))


def test_reregistration_with_changed_parents_conflicts(graph, session):
    # REPRODUCED flaw: only digest/tenant were compared, so changed parents were silently accepted.
    p1, p2 = _src(graph), _src(graph)
    child = make_env("chunk", [(p1.context_id, "v1")])
    graph.register_derivation(child)
    session.commit()
    data = child.model_dump(mode="json")
    data["parent_refs"] = [{"context_id": p2.context_id, "object_version": "v1"}]
    swapped = ContextEnvelope.model_validate(data)
    with pytest.raises(DuplicateContext):
        graph.register_derivation(swapped)
    assert graph.register_derivation(child).context_id == child.context_id  # identical is a no-op
    edges = session.scalars(select(DerivationEdge).where(DerivationEdge.child_id == child.context_id)).all()
    assert [(e.parent_id) for e in edges] == [p1.context_id]


# ------------------------------------------------------------------ 5. successor_of
def test_successor_of_round_trips_and_is_found(graph, session):
    old = _src(graph)
    new = make_env("source", successor_of=(old.context_id, "v1"))
    graph.register_source(new)
    newer = make_env("source", successor_of=(new.context_id, "v1"))
    graph.register_source(newer)
    # same-context newer version
    v2 = make_env("source", context_id=old.context_id, version="v2", valid_from=NOW)
    graph.register_source(v2)
    session.commit()
    row = session.get(ContextObject, (new.context_id, "v1"))
    assert (row.successor_context_id, row.successor_version) == (old.context_id, "v1")
    got = find_successors(session, TENANT, old.context_id, "v1")
    assert set(got) == {(new.context_id, "v1"), (newer.context_id, "v1"), (old.context_id, "v2")}
    assert find_successors(session, TENANT, newer.context_id, "v1") == []
    assert find_successors(session, "other-tenant", old.context_id, "v1") == []


def _superseded_setup(graph, session, *, with_successor: bool):
    s = _src(graph)
    c = make_env("chunk", [(s.context_id, "v1")])
    graph.register_derivation(c)
    succ = make_env("source", successor_of=(s.context_id, "v1") if with_successor else None)
    graph.register_source(succ)
    session.commit()
    ENG.accept(session, ev(s.context_id, "version_superseded", "v1"), now=NOW)
    return s, c, succ


def test_superseded_with_successor_under_new_context_id_is_refresh(graph, session):
    _, c, _ = _superseded_setup(graph, session, with_successor=True)
    r = authorize(session, req(c.context_id), NOW)
    assert r.decision == Decision.REFRESH and ReasonCode.ANCESTOR_SUPERSEDED in r.reason


def test_superseded_without_successor_link_is_deny(graph, session):
    _, c, _ = _superseded_setup(graph, session, with_successor=False)
    assert authorize(session, req(c.context_id), NOW).decision == Decision.DENY


def test_dead_successor_does_not_refresh(graph, session):
    _s, c, succ = _superseded_setup(graph, session, with_successor=True)
    ENG.accept(session, ev(succ.context_id, "deleted"), now=NOW)
    assert authorize(session, req(c.context_id), NOW).decision == Decision.DENY


# ------------------------------------------------------------------ 6. graph integrity
def test_verify_graph_healthy(chain, session):
    rep = verify_graph(session, TENANT)
    assert rep.ok and rep.cycle_suspects == []


def test_verify_graph_detects_corruption(session, chain):
    src, chunk, summ = (chain[k].context_id for k in ("source", "chunk", "summary"))
    # delete the chunk row: the edge chunk->source is orphaned (child gone), summary->chunk misses its parent
    session.execute(delete(ContextObject).where(ContextObject.context_id == chunk))
    session.commit()
    rep = verify_graph(session, TENANT)
    assert ((chunk, "v1"), (src, "v1")) in rep.orphan_edges
    assert ((summ, "v1"), (chunk, "v1")) in rep.missing_parents
    assert not rep.ok


def test_verify_graph_detects_cycle_and_resolver_terminates(session, chain):
    src, chunk = chain["source"].context_id, chain["chunk"].context_id
    session.add(DerivationEdge(child_id=src, child_version="v1", parent_id=chunk, parent_version="v1",
                               tenant_id=TENANT))
    session.commit()
    rep = verify_graph(session, TENANT)
    assert {(src, "v1"), (chunk, "v1")} <= set(rep.cycle_suspects)
    authorize(session, req(chain["memory"].context_id), NOW)  # must not hang


def test_verify_graph_dangling_successor(graph, session):
    ghost = str(uuid.uuid4())
    e = make_env("source", successor_of=(ghost, "v1"))
    graph.register_source(e)
    session.commit()
    assert verify_graph(session, TENANT).dangling_successors == [((e.context_id, "v1"), (ghost, "v1"))]


def test_verify_graph_is_tenant_scoped(graph, session, chain):
    graph.register_source(make_env("source", tenant="tenant-b"))
    session.execute(delete(ContextObject).where(ContextObject.context_id == chain["chunk"].context_id))
    session.commit()
    assert verify_graph(session, "tenant-b").ok
    assert not verify_graph(session, TENANT).ok


def test_corrupt_lineage_maps_to_unknown_lineage_uncertain(session, chain):
    session.execute(delete(ContextObject).where(ContextObject.context_id == chain["chunk"].context_id))
    session.commit()
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.decision == Decision.UNKNOWN
    assert ReasonCode.LINEAGE_UNCERTAIN in r.reason and ReasonCode.LINEAGE_INCOMPLETE in r.reason


# ------------------------------------------------------------------ 7. issuer-key compromise
def test_compromised_key_revokes_sources_and_descendants_idempotently(graph, session):
    KeyRegistry(session).register_key(TENANT, "k-bad", Ed25519PrivateKey.generate().public_key())
    KeyRegistry(session).register_key(TENANT, "k-ok", Ed25519PrivateKey.generate().public_key())
    s1 = make_env("source")
    s2 = make_env("source")
    s3 = make_env("source")
    for e, k in ((s1, "k-bad"), (s2, "k-bad"), (s3, "k-ok")):
        graph.register_source(e.model_copy(update={"issuer_key_id": k}))
    c1 = make_env("chunk", [(s1.context_id, "v1")])
    c2 = make_env("chunk", [(s2.context_id, "v1")])
    c3 = make_env("chunk", [(s3.context_id, "v1")])
    for c in (c1, c2, c3):
        graph.register_derivation(c)
    session.commit()
    assert affected_sources(session, TENANT, "k-bad") == sorted([(s1.context_id, "v1"), (s2.context_id, "v1")])
    assert affected_sources(session, "tenant-b", "k-bad") == []
    KeyRegistry(session).set_status(TENANT, "k-bad", "revoked")
    session.commit()

    ids = revoke_sources_for_key(session, TENANT, "k-bad", actor="secops", now=NOW)
    assert len(ids) == 2 and ids == [compromise_event_id("k-bad", c, v) for c, v in
                                     sorted([(s1.context_id, "v1"), (s2.context_id, "v1")])]
    for obj in (s1, s2, c1, c2):
        r = authorize(session, req(obj.context_id), NOW)
        assert r.decision == Decision.QUARANTINE and ReasonCode.ANCESTOR_QUARANTINED in r.reason
    for obj in (s3, c3):
        assert authorize(session, req(obj.context_id), NOW).decision == Decision.ALLOW

    n_events = len(session.scalars(select(RevocationEventRow)).all())
    again = revoke_sources_for_key(session, TENANT, "k-bad", actor="secops", now=NOW + timedelta(hours=1))
    assert again == ids
    assert len(session.scalars(select(RevocationEventRow)).all()) == n_events  # no new events


def test_compromise_workflow_derived_opt_in_and_bad_reason(graph, session):
    s = make_env("source").model_copy(update={"issuer_key_id": "k"})
    graph.register_source(s)
    c = make_env("chunk", [(s.context_id, "v1")]).model_copy(update={"issuer_key_id": "k"})
    graph.register_derivation(c)
    session.commit()
    assert affected_sources(session, TENANT, "k", include_derived=True) == sorted(
        [(s.context_id, "v1"), (c.context_id, "v1")]
    )
    with pytest.raises(Exception, match="reason"):
        revoke_sources_for_key(session, TENANT, "k", actor="x", reason="nonsense", now=NOW)


# ------------------------------------------------------------------ 8. migration 0004
def test_migration_0004_rewrites_legacy_empty_scopes_and_roundtrips(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    run_migrations(eng, "0003")
    cols = (
        "context_id, object_version, tenant_id, object_id, kind, content_digest, classification, "
        "trust_state, principal_scope, purpose_scope, valid_from, source_system, policy_version, tombstoned"
    )
    with eng.begin() as c:
        c.exec_driver_sql("INSERT INTO tenants (tenant_id, revocation_epoch) VALUES ('t', 0)")
        for cid, ps, pu in (("a", "[]", "[]"), ("b", '["x"]', "[]")):
            c.execute(
                text(f"INSERT INTO context_objects ({cols}) VALUES (:c,'v1','t','o','source','sha256:0',"
                     f"'internal','verified',:ps,:pu,'2026-01-01 00:00:00','s','p0',0)"),
                {"c": cid, "ps": ps, "pu": pu},
            )
    run_migrations(eng)
    with eng.connect() as c:
        rows = {r[0]: (r[1], r[2], r[3], r[4]) for r in c.execute(text(
            "SELECT context_id, principal_scope, purpose_scope, successor_context_id, successor_version "
            "FROM context_objects"))}
    assert rows["a"] == ("null", "null", None, None)  # legacy [] (unrestricted) -> JSON null
    assert rows["b"] == ('["x"]', "null", None, None)
    downgrade_migrations(eng, "0003")
    with eng.connect() as c:
        back = {r[0]: (r[1], r[2]) for r in c.execute(text(
            "SELECT context_id, principal_scope, purpose_scope FROM context_objects"))}
    assert back["a"] == ("[]", "[]")
    run_migrations(eng)
