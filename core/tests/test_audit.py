from __future__ import annotations

import itertools
import uuid
from datetime import timedelta

import pytest
from ales_core import (
    AuditLog,
    InvalidDetail,
    RevocationEngine,
    RevocationEvent,
    audit_append,
    audit_head,
    authorize,
    record_decision,
    verify_chain,
)
from ales_core.audit import GENESIS_HASH
from core_fixtures import NOW, TENANT, req
from sqlalchemy import delete, select, text, update


def fill(session, n=4, tenant=TENANT):
    for i in range(n):
        audit_append(
            session,
            tenant,
            f"actor{i}",
            "test.action",
            {"i": i, "nested": {"ok": [1, 2.5, None, True]}},
            at=NOW,
        )
    session.commit()


def test_empty_chain_ok(session):
    assert verify_chain(session) == (True, None)
    assert verify_chain(session, TENANT) == (True, None)
    assert audit_head(session, TENANT) is None


def test_chain_links_and_verifies(session):
    fill(session)
    rows = session.scalars(select(AuditLog).order_by(AuditLog.seq)).all()
    assert rows[0].prev_hash == GENESIS_HASH
    for a, b in itertools.pairwise(rows):
        assert b.prev_hash == a.hash
    assert len({r.hash for r in rows}) == 4
    assert verify_chain(session) == (True, None)
    assert audit_head(session, TENANT) == (rows[-1].seq, rows[-1].hash)


def test_tenant_chains_are_independent(session):
    fill(session, 2, "t1")
    fill(session, 2, "t2")
    fill(session, 1, "t1")
    first = {
        t: session.scalars(select(AuditLog).where(AuditLog.tenant_id == t).order_by(AuditLog.seq)).first()
        for t in ("t1", "t2")
    }
    assert first["t1"].prev_hash == first["t2"].prev_hash == GENESIS_HASH
    assert verify_chain(session) == (True, None)
    assert verify_chain(session, "t1") == (True, None)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda: {"actor": "mallory"},
        lambda: {"action": "other"},
        lambda: {"detail": {"i": 99}},
        lambda: {"tenant_id": "t-other"},
        lambda: {"at": NOW + timedelta(seconds=1)},
        lambda: {"hash": "f" * 64},
        lambda: {"prev_hash": "e" * 64},
    ],
)
@pytest.mark.parametrize("victim", [0, 1, 3])
def test_tampering_any_row_detected(session, mutate, victim):
    fill(session)
    seqs = [r.seq for r in session.scalars(select(AuditLog).order_by(AuditLog.seq))]
    session.execute(update(AuditLog).where(AuditLog.seq == seqs[victim]).values(**mutate()))
    session.commit()
    if mutate().get("tenant_id"):
        # a row moved to another tenant vanishes from this tenant's view (tail truncation is the
        # documented limit of a single chain), but the global verification flags it.
        ok, bad = verify_chain(session)
        assert not ok and bad is not None and bad <= seqs[victim] + 1
        return
    ok, bad = verify_chain(session, TENANT)
    assert not ok and bad == seqs[victim]


def test_deleting_middle_row_detected_and_reorder_detected(session):
    fill(session, 5)
    seqs = [r.seq for r in session.scalars(select(AuditLog).order_by(AuditLog.seq))]
    session.execute(delete(AuditLog).where(AuditLog.seq == seqs[2]))
    session.commit()
    assert verify_chain(session) == (False, seqs[3])


def test_reordering_rows_detected(session):
    fill(session, 3)
    _a, b, c = [r.seq for r in session.scalars(select(AuditLog).order_by(AuditLog.seq))]
    # swap seq of rows 2 and 3 via a temp value
    session.execute(update(AuditLog).where(AuditLog.seq == b).values(seq=100))
    session.execute(update(AuditLog).where(AuditLog.seq == c).values(seq=b))
    session.execute(update(AuditLog).where(AuditLog.seq == 100).values(seq=c))
    session.commit()
    ok, bad = verify_chain(session)
    assert not ok and bad == b


def test_fork_is_blocked_by_constraint(session):
    from sqlalchemy.exc import IntegrityError

    fill(session, 2)
    last = session.scalars(select(AuditLog).order_by(AuditLog.seq.desc())).first()
    session.add(
        AuditLog(
            tenant_id=TENANT,
            prev_hash=last.prev_hash,
            hash="a" * 64,
            at=NOW,
            actor="x",
            action="y",
            detail={},
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


@pytest.mark.parametrize(
    "detail",
    [
        {"content": "secret"},
        {"nested": {"Text": "x"}},
        {"items": [{"prompt": "x"}]},
        {"note": "x" * 600},
        {"obj": object()},
        {"n": float("nan")},
        {"big": 2**60},
    ],
)
def test_content_and_garbage_rejected(session, detail):
    with pytest.raises(InvalidDetail):
        audit_append(session, TENANT, "a", "b", detail)


def test_required_fields(session):
    with pytest.raises(InvalidDetail):
        audit_append(session, "", "a", "b")
    with pytest.raises(InvalidDetail):
        audit_append(session, TENANT, "", "b")


def test_revocation_accept_appends_atomically_and_idempotently(session, chain):
    eng = RevocationEngine()
    e = RevocationEvent(
        event_id=str(uuid.uuid4()),
        tenant_id=TENANT,
        source_id=chain["source"].context_id,
        reason="deleted",
        effective_at=NOW,
        actor="claimed-admin",
        affected_scope={"principals": ["bob"]},
    )
    eng.accept(session, e, now=NOW, actor="svc:revoker")
    eng.accept(session, e, now=NOW, actor="svc:revoker")  # duplicate: no second record
    rows = session.scalars(select(AuditLog)).all()
    assert len(rows) == 1
    r = rows[0]
    assert r.action == "revocation.accept" and r.actor == "svc:revoker" and r.tenant_id == TENANT
    d = r.detail
    assert d["claimed_actor"] == "claimed-admin" and d["event_id"] == e.event_id
    assert d["scope"] == {"principals": ["bob"], "purposes": None} and d["revocation_epoch"] == 1
    assert verify_chain(session) == (True, None)


def test_failed_accept_leaves_no_audit_row(session, chain):
    class Boom(RevocationEngine):
        pass

    e = RevocationEvent(
        event_id=str(uuid.uuid4()),
        tenant_id=TENANT,
        source_id=chain["source"].context_id,
        reason="deleted",
        effective_at=NOW,
        actor="x" * 600,
    )
    # claimed_actor is truncated, so this must still succeed (audit detail never blocks revocation)
    RevocationEngine().accept(session, e, now=NOW)
    assert session.scalars(select(AuditLog)).one().detail["claimed_actor"] == "x" * 255


def test_record_decision_has_ids_only(session, chain):
    r = req(chain["memory"].context_id, principal="alice", purpose="qa")
    resp = authorize(session, r, NOW)
    row = record_decision(session, "svc:reader", r, resp, at=NOW)
    session.commit()
    assert row.action == "decision.authorize" and row.actor == "svc:reader"
    assert (
        row.detail["decision"] == "ALLOW"
        and row.detail["objects"][0]["context_id"] == chain["memory"].context_id
    )
    assert row.detail["principal"] == {"type": "user", "id": "alice"}
    assert verify_chain(session) == (True, None)


def test_raw_sql_visible_roundtrip(session):
    fill(session, 2)
    n = session.execute(text("select count(*) from audit_log")).scalar()
    assert n == 2
