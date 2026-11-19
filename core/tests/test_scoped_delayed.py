"""effective_at, affected_scope, convergence and retroactive (unknown-source) revocation."""

from __future__ import annotations

import itertools
import uuid
from datetime import timedelta

import pytest
from ales_core import (
    AuditLog,
    Decision,
    GraphStore,
    InvalidationOutbox,
    ReasonCode,
    RevocationEngine,
    RevocationEvent,
    Tenant,
    authorize,
    create_all,
    is_tombstoned,
)
from core_fixtures import NOW, TENANT, make_env, req
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

ENG = RevocationEngine()


def ev(source_id, reason="acl_changed", version=None, at=None, scope=None, event_id=None, tenant=TENANT):
    return RevocationEvent(
        event_id=event_id or str(uuid.uuid4()),
        tenant_id=tenant,
        source_id=source_id,
        source_version=version,
        reason=reason,
        effective_at=at or NOW,
        affected_scope=scope,
    )


def accept(session, e):
    return ENG.accept(session, e, now=NOW)


def test_future_event_allows_now_denies_later(session, chain):
    mem = chain["memory"].context_id
    epoch = accept(session, ev(chain["source"].context_id, at=NOW + timedelta(hours=1)))
    assert epoch == 1
    r = authorize(session, req(mem), NOW)
    assert r.decision == Decision.ALLOW
    assert r.reason == [ReasonCode.OK]  # pending state is not leaked as a reason
    assert r.objects[0].reason == [ReasonCode.OK]
    assert r.revocation_epoch == 1  # epoch advanced at acceptance
    assert authorize(session, req(mem), NOW + timedelta(minutes=59, seconds=59)).decision == Decision.ALLOW
    late = authorize(session, req(mem), NOW + timedelta(hours=2))
    assert late.decision == Decision.DENY and late.reason == [ReasonCode.ANCESTOR_ACL_REVOKED]


def test_boundary_effective_at_equals_now_denies(session, chain):
    at = NOW + timedelta(hours=1)
    accept(session, ev(chain["source"].context_id, at=at))
    assert (
        authorize(session, req(chain["chunk"].context_id), at - timedelta(microseconds=1)).decision
        == Decision.ALLOW
    )
    assert authorize(session, req(chain["chunk"].context_id), at).decision == Decision.DENY


def test_naive_now_treated_as_utc(session, chain):
    accept(session, ev(chain["source"].context_id, at=NOW))
    assert (
        authorize(session, req(chain["chunk"].context_id), NOW.replace(tzinfo=None)).decision == Decision.DENY
    )


def test_delayed_purge_is_scheduled_for_effective_at(session, chain):
    at = NOW + timedelta(hours=1)
    accept(session, ev(chain["source"].context_id, at=at))
    rows = session.scalars(select(InvalidationOutbox)).all()
    assert len(rows) == 4 and all(r.available_at == at for r in rows)
    assert {r.store_kind for r in rows} == {"source", "chunk", "summary", "memory"}


def test_is_tombstoned_is_time_correct(session, chain):
    at = NOW + timedelta(hours=1)
    accept(session, ev(chain["source"].context_id, at=at))
    cid = chain["memory"].context_id
    assert not is_tombstoned(session, TENANT, cid, "v1", NOW)
    assert is_tombstoned(session, TENANT, cid, "v1", at)


def test_delayed_deadline_extends_to_new_descendants(graph, session, chain):
    accept(session, ev(chain["source"].context_id, at=NOW + timedelta(hours=1)))
    late = make_env("chunk", [(chain["source"].context_id, "v1")])
    graph.register_derivation(late)
    session.commit()
    assert authorize(session, req(late.context_id), NOW).decision == Decision.ALLOW
    assert authorize(session, req(late.context_id), NOW + timedelta(hours=1)).decision == Decision.DENY


def test_scoped_denies_only_matching_principal(session, chain):
    accept(session, ev(chain["source"].context_id, scope={"principals": ["bob"]}))
    mem = chain["memory"].context_id
    r = authorize(session, req(mem, principal="bob"), NOW)
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.ANCESTOR_ACL_REVOKED]
    ok = authorize(session, req(mem, principal="alice"), NOW)
    assert ok.decision == Decision.ALLOW and ok.reason == [ReasonCode.OK]
    assert ok.revocation_epoch == 1


def test_scoped_by_purpose_and_conjunction(session, chain):
    accept(session, ev(chain["source"].context_id, scope={"purposes": ["marketing"]}))
    mem = chain["memory"].context_id
    assert authorize(session, req(mem, purpose="marketing"), NOW).decision == Decision.DENY
    assert authorize(session, req(mem, purpose="qa"), NOW).decision == Decision.ALLOW
    accept(session, ev(chain["source"].context_id, scope={"principals": ["carol"], "purposes": ["qa"]}))
    assert authorize(session, req(mem, principal="carol", purpose="qa"), NOW).decision == Decision.DENY
    # both axes must match: carol on another purpose / another user on qa are unaffected
    assert authorize(session, req(mem, principal="carol", purpose="support"), NOW).decision == Decision.ALLOW
    assert authorize(session, req(mem, principal="dave", purpose="qa"), NOW).decision == Decision.ALLOW


def test_scoped_events_union_as_pairs_not_cross_product(session, chain):
    src = chain["source"].context_id
    accept(session, ev(src, scope={"principals": ["bob"], "purposes": ["x"]}))
    accept(session, ev(src, scope={"principals": ["carol"], "purposes": ["y"]}))
    mem = chain["memory"].context_id

    def d(p, purpose):
        return authorize(session, req(mem, principal=p, purpose=purpose), NOW).decision

    assert d("bob", "x") == Decision.DENY and d("carol", "y") == Decision.DENY
    assert d("bob", "y") == Decision.ALLOW and d("carol", "x") == Decision.ALLOW
    assert d("alice", "x") == Decision.ALLOW


def test_scoped_union_principal_only(session, chain):
    src = chain["source"].context_id
    accept(session, ev(src, scope={"principals": ["bob"]}))
    accept(session, ev(src, scope={"principals": ["carol"]}))
    mem = chain["memory"].context_id
    assert authorize(session, req(mem, principal="bob"), NOW).decision == Decision.DENY
    assert authorize(session, req(mem, principal="carol"), NOW).decision == Decision.DENY
    assert authorize(session, req(mem, principal="alice"), NOW).decision == Decision.ALLOW


def test_unscoped_beats_scoped_in_either_order(session, chain):
    src = chain["source"].context_id
    accept(session, ev(src, scope={"principals": ["bob"]}))
    accept(session, ev(src, reason="deleted"))
    r = authorize(session, req(chain["memory"].context_id, principal="alice"), NOW)
    assert r.decision == Decision.DENY and ReasonCode.ANCESTOR_DELETED in r.reason


@pytest.mark.parametrize("scope", [{}, {"principals": [], "purposes": []}, {"principals": None}])
def test_empty_scope_is_full_revocation(session, chain, scope):
    accept(session, ev(chain["source"].context_id, scope=scope))
    assert (
        authorize(session, req(chain["memory"].context_id, principal="anyone"), NOW).decision == Decision.DENY
    )


def test_scoped_never_widens_pre_existing_scope(graph, session):
    s = make_env("source", principals=["alice", "bob"])
    c = make_env("chunk", [(s.context_id, "v1")], principals=["alice", "bob"])
    graph.register_source(s)
    graph.register_derivation(c)
    session.commit()
    accept(session, ev(s.context_id, scope={"principals": ["bob"]}))
    assert authorize(session, req(c.context_id, principal="alice"), NOW).decision == Decision.ALLOW
    assert authorize(session, req(c.context_id, principal="mallory"), NOW).decision == Decision.DENY


def test_scoped_schedules_no_purge_and_no_flag(session, chain):
    accept(session, ev(chain["source"].context_id, scope={"principals": ["bob"]}))
    assert session.scalar(select(func.count()).select_from(InvalidationOutbox)) == 0
    assert not GraphStore(session).get_object(TENANT, chain["source"].context_id, "v1").tombstoned


def test_scoped_and_delayed_combined(session, chain):
    at = NOW + timedelta(hours=1)
    accept(session, ev(chain["source"].context_id, at=at, scope={"principals": ["bob"]}))
    mem = chain["memory"].context_id
    assert authorize(session, req(mem, principal="bob"), NOW).decision == Decision.ALLOW
    assert authorize(session, req(mem, principal="bob"), at).decision == Decision.DENY
    assert authorize(session, req(mem, principal="alice"), at).decision == Decision.ALLOW


def test_scoped_quarantine(session, chain):
    accept(session, ev(chain["source"].context_id, reason="poisoned", scope={"principals": ["bob"]}))
    mem = chain["memory"].context_id
    assert authorize(session, req(mem, principal="bob"), NOW).decision == Decision.QUARANTINE
    assert authorize(session, req(mem, principal="alice"), NOW).decision == Decision.ALLOW


def _fresh():
    eng = create_engine("sqlite:///:memory:", poolclass=StaticPool, connect_args={"check_same_thread": False})
    create_all(eng)
    return eng


def _snapshot(session, ids):
    out = {}
    for principal, purpose in (("alice", "qa"), ("bob", "qa"), ("carol", "x"), ("bob", "y")):
        for later in (NOW, NOW + timedelta(hours=3)):
            r = authorize(session, req(*ids, principal=principal, purpose=purpose), later)
            out[(principal, purpose, later)] = (
                r.decision,
                tuple(r.reason),
                tuple((o.decision, tuple(o.reason)) for o in r.objects),
            )
    return out


def test_all_orderings_converge():
    src = str(uuid.uuid4())
    events = [
        ev(
            src, "acl_changed", scope={"principals": ["bob"]}, event_id="00000000-0000-0000-0000-000000000001"
        ),
        ev(
            src,
            "deleted",
            scope={"principals": ["carol"], "purposes": ["x"]},
            event_id="00000000-0000-0000-0000-000000000002",
        ),
        ev(src, "expired", at=NOW + timedelta(hours=1), event_id="00000000-0000-0000-0000-000000000003"),
        ev(src, "acl_changed", scope={"purposes": ["y"]}, event_id="00000000-0000-0000-0000-000000000004"),
    ]
    results = []
    for perm in itertools.permutations(events):
        eng = _fresh()
        with Session(eng) as s:
            g = GraphStore(s)
            a = make_env("source", context_id=src)
            b = make_env("chunk", [(src, "v1")])
            g.register_source(a)
            g.register_derivation(b)
            s.commit()
            for e in perm:
                ENG.accept(s, e, now=NOW)
            results.append((_snapshot(s, [b.context_id]), s.get(Tenant, TENANT).revocation_epoch))
        eng.dispose()
    assert all(r == results[0] for r in results)
    assert results[0][1] == 4


def test_duplicate_delivery_is_noop(session, chain):
    e = ev(chain["source"].context_id, scope={"principals": ["bob"]})
    assert accept(session, e) == 1
    assert accept(session, e) == 1
    assert accept(session, e.model_copy()) == 1
    assert authorize(session, req(chain["memory"].context_id), NOW).revocation_epoch == 1


def test_unknown_source_persists_and_bumps_epoch(session):
    sid = str(uuid.uuid4())
    assert accept(session, ev(sid, "deleted", version="v1")) == 1
    assert authorize(session, req(str(uuid.uuid4())), NOW).revocation_epoch == 1


def test_retroactive_application_exact_version(graph, session):
    sid = str(uuid.uuid4())
    accept(session, ev(sid, "deleted", version="v1"))
    s1 = make_env("source", context_id=sid, version="v1")
    s2 = make_env("source", context_id=sid, version="v2")
    graph.register_source(s1)
    graph.register_source(s2)
    c = make_env("chunk", [(sid, "v1")])
    graph.register_derivation(c)
    session.commit()
    r = authorize(session, req((sid, "v1")), NOW)
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.ANCESTOR_DELETED]
    assert authorize(session, req((sid, "v2")), NOW).decision == Decision.ALLOW
    assert authorize(session, req(c.context_id), NOW).decision == Decision.DENY
    # applied immediately: purge scheduled for the late-registered object, flag set
    rows = session.scalars(select(InvalidationOutbox)).all()
    assert [(r.context_id, r.version, r.store_kind) for r in rows] == [(sid, "v1", "source")]
    assert graph.get_object(TENANT, sid, "v1").tombstoned
    assert not graph.get_object(TENANT, sid, "v2").tombstoned
    assert (
        session.scalar(
            select(func.count()).select_from(AuditLog).where(AuditLog.action == "revocation.apply_pending")
        )
        == 1
    )


def test_retroactive_null_version_hits_every_later_version(graph, session):
    sid = str(uuid.uuid4())
    accept(session, ev(sid, "acl_changed", version=None))
    for v in ("v1", "v2"):
        graph.register_source(make_env("source", context_id=sid, version=v))
    session.commit()
    for v in ("v1", "v2"):
        assert authorize(session, req((sid, v)), NOW).decision == Decision.DENY


def test_retroactive_scoped_and_delayed(graph, session):
    sid = str(uuid.uuid4())
    accept(session, ev(sid, at=NOW + timedelta(hours=1), scope={"principals": ["bob"]}))
    graph.register_source(make_env("source", context_id=sid))
    session.commit()
    assert authorize(session, req(sid, principal="bob"), NOW).decision == Decision.ALLOW
    assert authorize(session, req(sid, principal="bob"), NOW + timedelta(hours=1)).decision == Decision.DENY
    assert (
        authorize(session, req(sid, principal="alice"), NOW + timedelta(hours=1)).decision == Decision.ALLOW
    )
    assert session.scalar(select(func.count()).select_from(InvalidationOutbox)) == 0


def test_pending_tombstone_is_tenant_scoped(graph, session):
    sid = str(uuid.uuid4())
    accept(session, ev(sid, "deleted", tenant="tenant-b"))
    graph.register_source(make_env("source", context_id=sid, tenant=TENANT))
    session.commit()
    assert authorize(session, req(sid), NOW).decision == Decision.ALLOW


def test_valid_until_none_without_pending(session, chain):
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.valid_until is None and r.objects[0].valid_until is None


def test_valid_until_is_pending_effective_at(session, chain):
    at = NOW + timedelta(hours=1)
    accept(session, ev(chain["source"].context_id, at=at))
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.decision == Decision.ALLOW
    assert r.valid_until == at.strftime("%Y-%m-%dT%H:%M:%S.%fZ") == r.objects[0].valid_until


def test_valid_until_is_earliest_of_two_pending(session, chain):
    src = chain["source"].context_id
    accept(session, ev(src, at=NOW + timedelta(hours=5)))
    accept(session, ev(src, at=NOW + timedelta(hours=2)))
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.valid_until == (NOW + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    # once the earlier one is effective the bound moves to the remaining pending one (and the verdict is DENY)
    later = authorize(session, req(chain["memory"].context_id), NOW + timedelta(hours=3))
    assert later.decision == Decision.DENY
    assert later.valid_until == (NOW + timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def test_valid_until_excludes_already_effective(session, chain):
    accept(session, ev(chain["source"].context_id, at=NOW + timedelta(hours=1)))
    r = authorize(session, req(chain["memory"].context_id), NOW + timedelta(hours=2))
    assert r.decision == Decision.DENY and r.valid_until is None


def test_valid_until_ignores_pending_scoped_to_other_principal(session, chain):
    accept(
        session, ev(chain["source"].context_id, at=NOW + timedelta(hours=1), scope={"principals": ["bob"]})
    )
    mem = chain["memory"].context_id
    assert authorize(session, req(mem, principal="alice"), NOW).valid_until is None
    assert authorize(session, req(mem, principal="bob"), NOW).valid_until is not None


def test_valid_until_top_level_is_min_over_objects(session, chain):
    accept(session, ev(chain["memory"].context_id, at=NOW + timedelta(hours=4)))
    accept(session, ev(chain["chunk"].context_id, at=NOW + timedelta(hours=1)))
    r = authorize(session, req(chain["memory"].context_id, chain["source"].context_id), NOW)
    by_id = {o.context_id: o.valid_until for o in r.objects}
    assert by_id[chain["source"].context_id] is None
    assert r.valid_until == (NOW + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
