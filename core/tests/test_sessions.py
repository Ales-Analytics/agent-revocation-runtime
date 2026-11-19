from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from ales_core import (
    AuditLog,
    RevocationEngine,
    RevocationEvent,
    SessionError,
    SessionExposureRow,
    exposed_sessions,
    get_session_view,
    has_any_exposures,
    purge_expired,
    record_exposure,
    reset_session,
)
from core_fixtures import NOW, TENANT
from sqlalchemy import func, select

ALICE = {"type": "user", "id": "alice"}
BOB = {"type": "user", "id": "bob"}


def revoke(session, source_id, version=None, *, at=None, scope=None):
    ev = {
        "event_id": str(uuid.uuid4()),
        "tenant_id": TENANT,
        "source_id": source_id,
        "source_version": version,
        "reason": "acl_changed",
        "effective_at": at or NOW,
    }
    if scope:
        ev["affected_scope"] = scope
    RevocationEngine().accept(session, RevocationEvent(**ev), now=NOW)


def test_record_is_an_upsert_and_bounded(session, chain):
    c = chain["chunk"].context_id
    assert (
        record_exposure(session, TENANT, "s1", ALICE, "agent-1", [(c, "v1"), (c, "v1"), (c, None)], NOW) == 2
    )
    assert record_exposure(session, TENANT, "s1", ALICE, None, [(c, "v1")], NOW + timedelta(hours=1)) == 1
    session.commit()
    assert session.scalar(select(func.count()).select_from(SessionExposureRow)) == 2  # upsert, no duplicates
    row = session.scalars(select(SessionExposureRow).where(SessionExposureRow.object_version == "v1")).one()
    assert row.workload == "agent-1" and row.last_seen_at > row.first_seen_at
    with pytest.raises(SessionError):
        record_exposure(session, TENANT, "", ALICE, None, [(c, "v1")], NOW)
    with pytest.raises(SessionError):
        record_exposure(session, TENANT, "s1", ALICE, None, [(f"c{i}", "v") for i in range(1001)], NOW)
    view = get_session_view(session, TENANT, "s1", NOW)
    assert view is not None and (view.generation, view.exposure_count, view.needs_reset) == (0, 2, False)
    assert get_session_view(session, "other-tenant", "s1", NOW) is None  # tenant-scoped


def test_exposed_sessions_matches_versions_and_wildcards(session, chain):
    c = chain["chunk"].context_id
    record_exposure(session, TENANT, "exact", ALICE, None, [(c, "v1")], NOW)
    record_exposure(session, TENANT, "anyver", ALICE, None, [(c, None)], NOW)
    record_exposure(session, TENANT, "other-ver", ALICE, None, [(c, "v9")], NOW)
    assert exposed_sessions(session, TENANT, [(c, "v1")], NOW) == ["anyver", "exact"]
    assert exposed_sessions(session, TENANT, [c], NOW) == [
        "anyver",
        "exact",
        "other-ver",
    ]  # bare id = any version
    assert exposed_sessions(session, "tenant-b", [c], NOW) == []
    assert has_any_exposures(session, TENANT, NOW) and not has_any_exposures(session, "tenant-b", NOW)


def test_revocation_flags_exposed_sessions_through_descendants(session, chain):
    mem = chain["memory"].context_id
    other = chain["source"].context_id
    record_exposure(session, TENANT, "hit", ALICE, None, [(mem, "v1")], NOW)
    record_exposure(session, TENANT, "miss", ALICE, None, [("unrelated", "v1")], NOW)
    session.commit()
    revoke(session, other, "v1")
    hit = get_session_view(session, TENANT, "hit", NOW)
    assert (
        hit is not None and hit.needs_reset and hit.flag_reason and hit.flag_reason.startswith("revocation:")
    )
    miss = get_session_view(session, TENANT, "miss", NOW)
    assert miss is not None and not miss.needs_reset
    assert (
        session.scalars(select(AuditLog).where(AuditLog.action == "session.flag")).one().detail["flagged"]
        == 1
    )


def test_scoped_and_delayed_revocations(session, chain):
    mem = chain["memory"].context_id
    record_exposure(session, TENANT, "alice-s", ALICE, None, [(mem, "v1")], NOW)
    record_exposure(session, TENANT, "bob-s", BOB, None, [(mem, "v1")], NOW)
    session.commit()
    revoke(session, chain["source"].context_id, "v1", scope={"principals": ["bob"]})
    assert not get_session_view(session, TENANT, "alice-s", NOW).needs_reset
    assert get_session_view(session, TENANT, "bob-s", NOW).needs_reset
    # a delayed (future) revocation does not flag yet (documented gap)
    record_exposure(session, TENANT, "later", ALICE, None, [(mem, "v1")], NOW)
    revoke(session, chain["source"].context_id, "v1", at=NOW + timedelta(days=1))
    assert not get_session_view(session, TENANT, "later", NOW).needs_reset


def test_reset_bumps_generation_and_orphans_old_exposures(session, chain):
    mem = chain["memory"].context_id
    record_exposure(session, TENANT, "s", ALICE, None, [(mem, "v1")], NOW)
    session.commit()
    revoke(session, chain["source"].context_id, "v1")
    assert get_session_view(session, TENANT, "s", NOW).needs_reset
    view = reset_session(session, TENANT, "s", "operator", NOW)
    session.commit()
    assert (view.generation, view.needs_reset, view.exposure_count) == (1, False, 0)
    assert exposed_sessions(session, TENANT, [mem], NOW) == []  # the reset session no longer counts
    rec = session.scalars(select(AuditLog).where(AuditLog.action == "session.reset")).one()
    assert rec.actor == "operator" and rec.detail["generation_to"] == 1 and rec.detail["was_flagged"] is True
    # exposures after the reset belong to the new generation and are flagged by later revocations
    record_exposure(session, TENANT, "s", ALICE, None, [(mem, "v1")], NOW)
    assert exposed_sessions(session, TENANT, [mem], NOW) == ["s"]
    with pytest.raises(SessionError):
        reset_session(session, TENANT, "nope", "operator", NOW)
    with pytest.raises(SessionError):
        reset_session(session, "tenant-b", "s", "operator", NOW)


def test_retention_expiry_and_purge(session, chain):
    mem = chain["memory"].context_id
    record_exposure(session, TENANT, "short", ALICE, None, [(mem, "v1")], NOW, retention=timedelta(hours=1))
    record_exposure(session, TENANT, "long", ALICE, None, [(mem, "v1")], NOW, retention=timedelta(days=7))
    session.commit()
    later = NOW + timedelta(hours=2)
    assert exposed_sessions(session, TENANT, [mem], later) == [
        "long"
    ]  # expired rows never count, even unpurged
    assert get_session_view(session, TENANT, "short", later) is None
    removed = purge_expired(session, later)
    session.commit()
    assert removed == 2  # one exposure + one state row
    assert session.scalar(select(func.count()).select_from(SessionExposureRow)) == 1
    assert purge_expired(session, later) == 0
    # a revocation after expiry flags nothing for the forgotten session
    revoke(session, chain["source"].context_id, "v1")
    assert get_session_view(session, TENANT, "short", later) is None
