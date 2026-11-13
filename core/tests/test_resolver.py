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


def test_cross_tenant_id_is_indistinguishable_from_unknown(session, chain):
    from ales_core import authorize_ex

    foreign = authorize_ex(session, req(chain["source"].context_id, tenant="tenant-z"), NOW)
    unknown = authorize_ex(session, req(str(uuid.uuid4()), tenant="tenant-z"), NOW)
    for out in (foreign, unknown):
        assert out.response.decision == Decision.UNKNOWN
        assert out.response.reason == [ReasonCode.OBJECT_UNKNOWN]
        assert out.response.objects[0].reason == [ReasonCode.OBJECT_UNKNOWN]
    # identical wire shape apart from the random trace id / the context id itself
    f, u = foreign.response.model_dump(), unknown.response.model_dump()
    for d in (f, u):
        d.pop("trace_id")
        d["objects"][0].pop("context_id")
    assert f == u
    # the distinction exists only in the audit detail
    assert foreign.tenant_mismatch and foreign.audit_extra()["tenant_mismatch"] is True
    assert not unknown.tenant_mismatch and "tenant_mismatch" not in unknown.audit_extra()


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


# ----------------------------------------------------------------------------- v0.3 policy integration


def _install(session, rules, default="allow", version=1, policy_id="pol"):
    from ales_core import PolicyDocument, PolicyStore

    PolicyStore.install(
        session,
        PolicyDocument.model_validate(
            {"policy_id": policy_id, "tenant_id": "tenant-a", "version": version, "rules": rules,
             "default_action": default, "created_by": "admin"}
        ),
    )
    PolicyStore.activate(session, "tenant-a", policy_id, version, actor="admin")
    session.commit()


def test_policy_version_is_p0_without_document(session, chain):
    assert authorize(session, req(chain["memory"].context_id), NOW).policy_version == "p0"


def test_policy_version_string_and_allow_unchanged(session, chain):
    _install(session, [{"rule_id": "ok", "effect": "allow"}], version=3)
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.policy_version == "pol@3" and r.decision == Decision.ALLOW and r.reason == [ReasonCode.OK]


def test_policy_deny_restricts_allow(session, chain):
    _install(session, [{"rule_id": "no-bob", "effect": "deny", "subjects": {"principals": ["bob"]}}])
    assert authorize(session, req(chain["memory"].context_id, principal="alice"), NOW).decision == Decision.ALLOW
    r = authorize(session, req(chain["memory"].context_id, principal="bob"), NOW)
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.POLICY_DENIED]
    assert r.objects[0].decision == Decision.DENY


def test_policy_default_deny_and_obligation(session, chain):
    _install(session, [], default="deny")
    assert authorize(session, req(chain["memory"].context_id), NOW).reason == [ReasonCode.POLICY_DENIED]
    _install(session, [{"rule_id": "cap", "effect": "allow", "obligations": {"max_classification": "public"}}],
             version=2)
    r = authorize(session, req(chain["memory"].context_id), NOW)  # chain is "internal"
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.POLICY_DENIED]


def test_policy_uses_effective_lineage_classification(graph, session):
    s = make_env("source", classification="restricted")
    c = make_env("chunk", [(s.context_id, "v1")], classification="restricted")
    graph.register_source(s)
    graph.register_derivation(c)
    session.commit()
    _install(session, [{"rule_id": "cap", "effect": "allow", "obligations": {"max_classification": "internal"}}])
    assert authorize(session, req(c.context_id), NOW).decision == Decision.DENY


def test_policy_lineage_quarantine_stands(session, chain):
    _install(session, [{"rule_id": "d", "effect": "deny"}])
    RevocationEngine().accept(
        session,
        RevocationEvent(event_id=str(uuid.uuid4()), tenant_id="tenant-a", source_id=chain["source"].context_id,
                        reason="poisoned", effective_at=NOW),
        now=NOW,
    )
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.decision == Decision.QUARANTINE and r.reason == [ReasonCode.ANCESTOR_QUARANTINED]


def test_policy_tools_and_risk_selectors(session, chain):
    from ales_core import AuthorizeRequest, ObjectRef, Principal

    _install(session, [{"rule_id": "shell", "effect": "human_review", "resources": {"tools": ["shell"]},
                        "risk": "high"}])

    def mk(tools, risk):
        return AuthorizeRequest(tenant_id="tenant-a", principal=Principal(type="user", id="alice"), purpose="qa",
                                objects=[ObjectRef(context_id=chain["memory"].context_id)], tools=tools, risk=risk)

    assert authorize(session, mk(["shell"], "high"), NOW).decision == Decision.HUMAN_REVIEW
    assert authorize(session, mk(["shell"], "low"), NOW).decision == Decision.ALLOW
    assert authorize(session, mk(["search"], "high"), NOW).decision == Decision.ALLOW
    assert authorize(session, mk([], None), NOW).decision == Decision.ALLOW


def test_require_fresh_lineage_denies_unknown_even_for_public(session, chain):
    unknown = str(uuid.uuid4())
    _install(session, [{"rule_id": "f", "effect": "allow", "obligations": {"require_fresh_lineage": True}}])
    r = authorize(session, req(unknown), NOW)
    assert r.decision == Decision.DENY and ReasonCode.POLICY_DENIED in r.reason
    # complete lineage is untouched
    assert authorize(session, req(chain["memory"].context_id), NOW).decision == Decision.ALLOW
    # and without the obligation UNKNOWN stays UNKNOWN
    _install(session, [{"rule_id": "f", "effect": "allow"}], version=2)
    assert authorize(session, req(unknown), NOW).decision == Decision.UNKNOWN


def test_require_fresh_lineage_does_not_deny_refresh(graph, session):
    s1 = make_env("source", context_id=str(uuid.uuid4()), version="v1")
    s2 = make_env("source", context_id=s1.context_id, version="v2")
    c = make_env("chunk", [(s1.context_id, "v1")])
    graph.register_source(s1)
    graph.register_source(s2)
    graph.register_derivation(c)
    session.commit()
    RevocationEngine().accept(
        session,
        RevocationEvent(event_id=str(uuid.uuid4()), tenant_id="tenant-a", source_id=s1.context_id,
                        source_version="v1", reason="version_superseded", effective_at=NOW),
        now=NOW,
    )
    _install(session, [{"rule_id": "f", "effect": "allow", "obligations": {"require_fresh_lineage": True}}])
    assert authorize(session, req(c.context_id), NOW).decision == Decision.REFRESH


def test_old_wire_request_still_valid():
    from ales_core import AuthorizeRequest

    r = AuthorizeRequest.model_validate(
        {"tenant_id": "t", "principal": {"type": "user", "id": "a"}, "purpose": "p", "objects": [{"context_id": "x"}]}
    )
    assert r.tools == [] and r.risk is None
    with pytest.raises(ValueError):
        AuthorizeRequest.model_validate(
            {"tenant_id": "t", "principal": {"type": "user", "id": "a"}, "purpose": "p",
             "objects": [{"context_id": "x"}], "risk": "extreme"}
        )
