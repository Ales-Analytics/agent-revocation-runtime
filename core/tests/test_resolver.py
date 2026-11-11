from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from ales_core import (
    Decision,
    ReasonCode,
    RevocationEngine,
    RevocationEvent,
    authorize,
    sign_envelope,
    verify_envelope,
    verify_event,
)
from ales_core.models import DECISION_SEVERITY
from core_fixtures import NOW, make_env, req
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_allow_happy_path(session, chain):
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.decision == Decision.ALLOW
    assert r.reason == [ReasonCode.OK]
    assert r.objects[0].version == "v1"
    uuid.UUID(r.trace_id)


def test_unknown_object_is_unknown_not_deny(session):
    r = authorize(session, req(str(uuid.uuid4())), NOW)
    assert r.decision == Decision.UNKNOWN
    assert r.reason == [ReasonCode.OBJECT_UNKNOWN]
    assert r.revocation_epoch == 0


def test_unknown_version(session, chain):
    r = authorize(session, req((chain["source"].context_id, "v9")), NOW)
    assert r.decision == Decision.UNKNOWN


def test_tenant_mismatch(session, chain):
    r = authorize(session, req(chain["source"].context_id, tenant="tenant-z"), NOW)
    assert r.decision == Decision.DENY
    assert r.reason == [ReasonCode.TENANT_MISMATCH]


def test_principal_scoping(graph, session):
    s = make_env("source", principals=["alice"])
    c = make_env("chunk", [(s.context_id, "v1")], principals=["alice"])
    graph.register_source(s)
    graph.register_derivation(c)
    session.commit()
    assert authorize(session, req(c.context_id, principal="alice"), NOW).decision == Decision.ALLOW
    r = authorize(session, req(c.context_id, principal="bob"), NOW)
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.PRINCIPAL_NOT_IN_SCOPE]


def test_purpose_scoping(graph, session):
    s = make_env("source", purposes=["support"])
    graph.register_source(s)
    session.commit()
    assert authorize(session, req(s.context_id, purpose="support"), NOW).decision == Decision.ALLOW
    r = authorize(session, req(s.context_id, purpose="marketing"), NOW)
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.PURPOSE_NOT_IN_SCOPE]


def test_empty_scope_is_unrestricted(graph, session):
    s = make_env("source")
    graph.register_source(s)
    session.commit()
    assert (
        authorize(session, req(s.context_id, principal="anyone", purpose="anything"), NOW).decision
        == Decision.ALLOW
    )


def test_ancestor_scope_restricts_descendant(graph, session):
    # parent scoped to alice; a derivative must be scoped too, and disjoint parents are refused at registration
    s = make_env("source", principals=["alice", "bob"])
    c = make_env("chunk", [(s.context_id, "v1")], principals=["alice"])
    graph.register_source(s)
    graph.register_derivation(c)
    session.commit()
    assert authorize(session, req(c.context_id, principal="bob"), NOW).decision == Decision.DENY


def test_quarantined_trust_state(graph, session):
    s = make_env("source", trust="quarantined")
    c = make_env("chunk", [(s.context_id, "v1")], trust="quarantined")
    graph.register_source(s)
    graph.register_derivation(c)
    session.commit()
    r = authorize(session, req(c.context_id), NOW)
    assert r.decision == Decision.QUARANTINE and r.reason == [ReasonCode.ANCESTOR_QUARANTINED]


def test_severity_ordering_table():
    order = [
        Decision.ALLOW,
        Decision.REFRESH,
        Decision.HUMAN_REVIEW,
        Decision.REDACT,
        Decision.UNKNOWN,
        Decision.QUARANTINE,
        Decision.DENY,
    ]
    assert [DECISION_SEVERITY[d] for d in order] == sorted(DECISION_SEVERITY.values())
    assert len(set(DECISION_SEVERITY.values())) == 7


def test_overall_is_worst_across_objects(graph, session):
    ok = make_env("source")
    unk = str(uuid.uuid4())
    quar = make_env("source", trust="quarantined")
    gone = make_env("source")
    for s in (ok, quar, gone):
        graph.register_source(s)
    session.commit()
    RevocationEngine().accept(
        session,
        RevocationEvent(
            event_id=str(uuid.uuid4()),
            tenant_id="tenant-a",
            source_id=gone.context_id,
            reason="deleted",
            effective_at=NOW,
        ),
    )

    r = authorize(session, req(ok.context_id, unk), NOW)
    assert r.decision == Decision.UNKNOWN  # not silently converted
    assert r.reason == [ReasonCode.OBJECT_UNKNOWN]

    r = authorize(session, req(ok.context_id, unk, quar.context_id), NOW)
    assert r.decision == Decision.QUARANTINE

    r = authorize(session, req(ok.context_id, unk, quar.context_id, gone.context_id), NOW)
    assert r.decision == Decision.DENY
    assert [v.decision for v in r.objects] == [
        Decision.ALLOW,
        Decision.UNKNOWN,
        Decision.QUARANTINE,
        Decision.DENY,
    ]
    assert set(r.reason) == {
        ReasonCode.OBJECT_UNKNOWN,
        ReasonCode.ANCESTOR_QUARANTINED,
        ReasonCode.ANCESTOR_DELETED,
    }


def test_deterministic_given_state(session, chain):
    a = authorize(session, req(chain["memory"].context_id), NOW)
    b = authorize(session, req(chain["memory"].context_id), NOW)
    assert a.model_dump(exclude={"trace_id"}) == b.model_dump(exclude={"trace_id"})
    assert a.trace_id != b.trace_id


def test_signing_roundtrip():
    key = Ed25519PrivateKey.generate()
    env = make_env("source")
    sig = sign_envelope(env, key)
    signed = env.model_copy(update={"signature": sig})
    assert verify_envelope(signed, key.public_key())
    tampered = signed.model_copy(update={"classification": "public"})
    assert not verify_envelope(tampered, key.public_key())
    assert not verify_envelope(signed, Ed25519PrivateKey.generate().public_key())
    assert not verify_envelope(env, key.public_key())  # unsigned
    # same dict form verifies too
    assert verify_envelope(signed.model_dump(mode="json"), key.public_key())


def test_event_signing():
    from ales_core import sign_event

    key = Ed25519PrivateKey.generate()
    ev = RevocationEvent(
        event_id=str(uuid.uuid4()),
        tenant_id="t",
        source_id="s",
        reason="deleted",
        effective_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    ev = ev.model_copy(update={"signature": sign_event(ev, key)})
    assert verify_event(ev, key.public_key())
    assert not verify_event(ev.model_copy(update={"reason": "expired"}), key.public_key())


def test_envelope_schema_rules():
    with pytest.raises(ValueError):
        make_env("chunk")  # non-source needs parents
    with pytest.raises(ValueError):
        make_env("source", [(str(uuid.uuid4()), "v1")])
