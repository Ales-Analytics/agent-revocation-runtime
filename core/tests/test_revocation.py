from __future__ import annotations

import uuid
from datetime import timedelta

from ales_core import (
    Decision,
    InvalidationOutbox,
    ReasonCode,
    RevocationEngine,
    RevocationEvent,
    RevocationEventRow,
    authorize,
)
from core_fixtures import NOW, TENANT, make_env, req
from sqlalchemy import func, select


def event(source_id, reason="acl_changed", version=None, tenant=TENANT, event_id=None):
    return RevocationEvent(
        event_id=event_id or str(uuid.uuid4()),
        tenant_id=tenant,
        source_id=source_id,
        source_version=version,
        reason=reason,
        effective_at=NOW,
    )


def test_blueprint_worked_example(session, chain):
    ids = [chain[k].context_id for k in ("source", "chunk", "summary", "memory")]
    before = authorize(session, req(*ids), NOW)
    assert before.decision == Decision.ALLOW and before.reason == [ReasonCode.OK]
    assert before.revocation_epoch == 0

    epoch = RevocationEngine().accept(session, event(chain["source"].context_id, "acl_changed", "v1"))
    assert epoch == 1

    after = authorize(session, req(*ids), NOW)
    assert after.decision == Decision.DENY
    assert after.revocation_epoch == 1
    assert after.policy_version == "p0" and after.trace_id
    assert len(after.objects) == 4
    for v in after.objects:
        assert v.decision == Decision.DENY
        assert v.reason == [ReasonCode.ANCESTOR_ACL_REVOKED]

    rows = session.scalars(select(InvalidationOutbox)).all()
    assert len(rows) == 4
    assert {r.context_id for r in rows} == set(ids)
    assert all(not r.dispatched and r.reason == "acl_changed" for r in rows)


def test_idempotent_reaccept(session, chain):
    ev = event(chain["source"].context_id, "deleted")
    eng = RevocationEngine()
    assert eng.accept(session, ev) == 1
    assert eng.accept(session, ev) == 1
    assert session.scalar(select(func.count()).select_from(RevocationEventRow)) == 1
    assert session.scalar(select(func.count()).select_from(InvalidationOutbox)) == 4
    assert authorize(session, req(chain["memory"].context_id), NOW).revocation_epoch == 1


def test_new_event_increments_epoch_again(session, chain):
    eng = RevocationEngine()
    assert eng.accept(session, event(chain["source"].context_id, "deleted")) == 1
    assert eng.accept(session, event(chain["source"].context_id, "deleted")) == 2


def test_purge_failed_still_denies(session, chain):
    RevocationEngine().accept(session, event(chain["source"].context_id, "deleted"))
    # purge never dispatched (adapter down): outbox rows remain undispatched
    assert (
        session.scalar(
            select(func.count())
            .select_from(InvalidationOutbox)
            .where(InvalidationOutbox.dispatched.is_(False))
        )
        == 4
    )
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.decision == Decision.DENY
    assert r.reason == [ReasonCode.ANCESTOR_DELETED]


def test_tombstone_only_requested_version(graph, session):
    v1 = make_env("source", version="v1")
    v2 = make_env("source", context_id=v1.context_id, version="v2")
    graph.register_source(v1)
    graph.register_source(v2)
    session.commit()
    RevocationEngine().accept(session, event(v1.context_id, "deleted", "v1"))
    assert authorize(session, req((v1.context_id, "v1")), NOW).decision == Decision.DENY
    assert authorize(session, req((v1.context_id, "v2")), NOW).decision == Decision.ALLOW
    RevocationEngine().accept(session, event(v1.context_id, "deleted", None))
    assert authorize(session, req((v1.context_id, "v2")), NOW).decision == Decision.DENY


def test_superseded_with_newer_version_refreshes(graph, session):
    v1 = make_env("source", version="v1")
    v2 = make_env("source", context_id=v1.context_id, version="v2")
    chunk = make_env("chunk", [(v1.context_id, "v1")])
    graph.register_source(v1)
    graph.register_source(v2)
    graph.register_derivation(chunk)
    session.commit()
    RevocationEngine().accept(session, event(v1.context_id, "version_superseded", "v1"))
    r = authorize(session, req(chunk.context_id), NOW)
    assert r.decision == Decision.REFRESH
    assert r.reason == [ReasonCode.ANCESTOR_SUPERSEDED]


def _supersede_setup(graph, session):
    a1 = make_env("source", version="v1")
    a2 = make_env("source", context_id=a1.context_id, version="v2")
    b1 = make_env("source", version="v1")
    chunk = make_env("chunk", [(a1.context_id, "v1"), (b1.context_id, "v1")])
    graph.register_source(a1)
    graph.register_source(a2)
    graph.register_source(b1)
    graph.register_derivation(chunk)
    session.commit()
    return a1, b1, chunk


def test_refresh_is_per_tombstone_mixed_lineage_denies(graph, session):
    a1, b1, chunk = _supersede_setup(graph, session)
    RevocationEngine().accept(session, event(a1.context_id, "version_superseded", "v1"))
    r = authorize(session, req(chunk.context_id), NOW)
    assert r.decision == Decision.REFRESH  # A alone: has a live successor
    RevocationEngine().accept(session, event(b1.context_id, "version_superseded", "v1"))
    r = authorize(session, req(chunk.context_id), NOW)
    assert r.decision == Decision.DENY  # B has no live successor: the superseded ancestor stays DENY
    assert r.reason == [ReasonCode.ANCESTOR_SUPERSEDED]


def test_refresh_not_granted_by_unrelated_sibling(graph, session):
    _a1, b1, chunk = _supersede_setup(graph, session)
    # only B superseded; A (which has a successor) is untouched, so B's lineage cannot be refreshed
    RevocationEngine().accept(session, event(b1.context_id, "version_superseded", "v1"))
    assert authorize(session, req(chunk.context_id), NOW).decision == Decision.DENY


def test_superseded_without_newer_version_denies(session, chain):
    RevocationEngine().accept(session, event(chain["source"].context_id, "version_superseded", "v1"))
    r = authorize(session, req(chain["chunk"].context_id), NOW)
    assert r.decision == Decision.DENY
    assert r.reason == [ReasonCode.ANCESTOR_SUPERSEDED]


def test_poisoned_quarantines(session, chain):
    RevocationEngine().accept(session, event(chain["source"].context_id, "poisoned"))
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.decision == Decision.QUARANTINE
    assert r.reason == [ReasonCode.ANCESTOR_QUARANTINED]


def test_compromised_quarantines(session, chain):
    RevocationEngine().accept(session, event(chain["source"].context_id, "compromised"))
    assert authorize(session, req(chain["summary"].context_id), NOW).decision == Decision.QUARANTINE


def test_expired_source_denies_without_event(graph, session):
    s = make_env("source", expires_at=NOW + timedelta(days=1))
    c = make_env("chunk", [(s.context_id, "v1")], expires_at=NOW + timedelta(days=1))
    graph.register_source(s)
    graph.register_derivation(c)
    session.commit()
    assert authorize(session, req(c.context_id), NOW).decision == Decision.ALLOW
    r = authorize(session, req(c.context_id), NOW + timedelta(days=2))
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.ANCESTOR_EXPIRED]


def test_expired_ancestor_denies_even_if_descendant_unbounded(graph, session):
    s = make_env("source", expires_at=NOW + timedelta(days=1))
    c = make_env("chunk", [(s.context_id, "v1")], expires_at=NOW + timedelta(days=1))
    graph.register_source(s)
    graph.register_derivation(c)
    # tamper: descendant row loses its own expiry; ancestor walk must still deny
    graph.get_object(TENANT, c.context_id, "v1").expires_at = None
    session.commit()
    assert authorize(session, req(c.context_id), NOW + timedelta(days=2)).decision == Decision.DENY


def test_expired_revocation_reason_denies(session, chain):
    RevocationEngine().accept(session, event(chain["source"].context_id, "expired"))
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.ANCESTOR_EXPIRED]


def test_multi_parent_one_revoked_denies(graph, session):
    a = make_env("source")
    b = make_env("source")
    summ = make_env("summary", [(a.context_id, "v1"), (b.context_id, "v1")])
    other = make_env("chunk", [(b.context_id, "v1")])
    for s in (a, b):
        graph.register_source(s)
    graph.register_derivation(summ)
    graph.register_derivation(other)
    session.commit()
    RevocationEngine().accept(session, event(a.context_id, "acl_changed"))
    r = authorize(session, req(summ.context_id, other.context_id), NOW)
    by_id = {v.context_id: v for v in r.objects}
    assert by_id[summ.context_id].decision == Decision.DENY
    assert by_id[summ.context_id].reason == [ReasonCode.ANCESTOR_ACL_REVOKED]
    assert by_id[other.context_id].decision == Decision.ALLOW
    assert r.decision == Decision.DENY


def test_revocation_is_tenant_scoped(graph, session, chain):
    other = make_env("source", tenant="tenant-b", context_id=str(uuid.uuid4()))
    graph.register_source(other)
    session.commit()
    # event in tenant-b naming a tenant-a object must not touch it
    RevocationEngine().accept(session, event(chain["source"].context_id, "deleted", tenant="tenant-b"))
    assert authorize(session, req(chain["memory"].context_id), NOW).decision == Decision.ALLOW
    assert authorize(session, req(chain["memory"].context_id), NOW).revocation_epoch == 0
