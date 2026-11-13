from __future__ import annotations

import itertools
import uuid
from datetime import timedelta

import pytest
from ales_core import (
    AuthorizeRequest,
    Decision,
    GraphStore,
    ObjectRef,
    PolicyDocument,
    PolicyError,
    PolicyStore,
    Principal,
    ReasonCode,
    RevocationEngine,
    RevocationEvent,
    authorize,
    create_all,
    evaluate_policy,
    verify_chain,
)
from ales_core.db import AuditLog, PolicyDocumentRow
from ales_core.models import DECISION_SEVERITY
from ales_core.policy import Effect
from core_fixtures import NOW, TENANT, make_env, req
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


def mkdoc(rules=None, default="deny", *, version=1, policy_id="pol", tenant=TENANT) -> PolicyDocument:
    return PolicyDocument.model_validate(
        {
            "policy_id": policy_id,
            "tenant_id": tenant,
            "version": version,
            "rules": rules or [],
            "default_action": default,
            "created_by": "admin",
        }
    )


def ctx(**kw):
    base = {
        "principal_id": "alice",
        "principal_type": "user",
        "agent_id": None,
        "purpose": "qa",
        "objects": [{"kind": "chunk", "classification": "internal"}],
        "tools": [],
        "risk": None,
    }
    base.update(kw)
    return base


def effect_of(rules, default="deny", **kw):
    return evaluate_policy(mkdoc(rules, default), ctx(**kw))


# ----------------------------------------------------------------------------- validation


def test_validation_rejects_bad_documents():
    with pytest.raises(ValidationError):
        mkdoc(policy_id="")
    with pytest.raises(ValidationError):
        mkdoc(policy_id="a@b")
    with pytest.raises(ValidationError):
        mkdoc(version=0)
    with pytest.raises(ValidationError):
        mkdoc([{"rule_id": "r", "effect": "allow"}, {"rule_id": "r", "effect": "deny"}])
    with pytest.raises(ValidationError):  # bad classification in selector
        mkdoc([{"rule_id": "r", "effect": "deny", "resources": {"classifications": ["secret"]}}])
    with pytest.raises(ValidationError):  # bad max_classification
        mkdoc([{"rule_id": "r", "effect": "allow", "obligations": {"max_classification": "secret"}}])
    with pytest.raises(ValidationError):  # unknown selector key must not be silently ignored
        mkdoc([{"rule_id": "r", "effect": "deny", "subjects": {"principal": ["x"]}}])
    with pytest.raises(ValidationError):  # empty selector list is ambiguous
        mkdoc([{"rule_id": "r", "effect": "deny", "purposes": []}])
    with pytest.raises(ValidationError):
        mkdoc([{"rule_id": "r", "effect": "maybe"}])
    with pytest.raises(ValidationError):
        mkdoc([{"rule_id": "r", "effect": "deny", "risk": "extreme"}])


def test_default_action_defaults_to_deny():
    d = PolicyDocument.model_validate({"policy_id": "p", "tenant_id": "t", "version": 1, "created_by": "a"})
    assert d.default_action == Effect.DENY
    assert d.policy_version == "p@1"


# ----------------------------------------------------------------------------- matching matrix


def test_default_action_applies_when_nothing_matches():
    for default, eff in (("allow", "allow"), ("deny", "deny"), ("human_review", "human_review")):
        o = effect_of([{"rule_id": "r", "effect": "deny", "purposes": ["other"]}], default)
        assert o.effect == eff and o.rule_id is None


def test_empty_rules_uses_default():
    assert effect_of([], "allow").effect == Effect.ALLOW


def test_first_match_wins_in_order():
    rules = [
        {"rule_id": "a", "effect": "allow", "subjects": {"principals": ["alice"]}},
        {"rule_id": "b", "effect": "deny"},
    ]
    o = effect_of(rules)
    assert (o.effect, o.rule_id) == (Effect.ALLOW, "a")
    rules.reverse()
    o = effect_of(rules)
    assert (o.effect, o.rule_id) == (Effect.DENY, "b")


@pytest.mark.parametrize(
    "selector,value,expected",
    [
        ({"subjects": {"principals": ["alice"]}}, {}, True),
        ({"subjects": {"principals": ["bob"]}}, {}, False),
        ({"subjects": {"principals": ["*"]}}, {}, True),
        ({"subjects": {"principals": ["bob", "alice"]}}, {}, True),
        ({"subjects": {"principal_types": ["agent"]}}, {}, False),
        ({"subjects": {"principal_types": ["user"]}}, {}, True),
        ({"subjects": {"agents": ["a1"]}}, {"agent_id": "a1"}, True),
        ({"subjects": {"agents": ["a1"]}}, {"agent_id": "a2"}, False),
        ({"subjects": {"agents": ["a1"]}}, {"agent_id": None}, False),
        ({"subjects": {"agents": ["*"]}}, {"agent_id": None}, False),
        ({"subjects": {"agents": ["*"]}}, {"agent_id": "a9"}, True),
        ({"purposes": ["qa"]}, {}, True),
        ({"purposes": ["billing"]}, {}, False),
        ({"purposes": ["*"]}, {}, True),
        ({"resources": {"kinds": ["chunk"]}}, {}, True),
        ({"resources": {"kinds": ["memory"]}}, {}, False),
        ({"resources": {"classifications": ["internal"]}}, {}, True),
        ({"resources": {"classifications": ["restricted"]}}, {}, False),
        ({"resources": {"tools": ["web"]}}, {"tools": ["web"]}, True),
        ({"resources": {"tools": ["web"]}}, {"tools": ["mail"]}, False),
        ({"resources": {"tools": ["web"]}}, {"tools": []}, False),
        ({"resources": {"tools": ["*"]}}, {"tools": []}, False),  # resource selectors never match "no tool"
        ({"risk": "high"}, {"risk": "high"}, True),
        ({"risk": "high"}, {"risk": "low"}, False),
        ({"risk": "high"}, {"risk": None}, False),
        ({"subjects": {"principals": ["alice"]}, "purposes": ["billing"]}, {}, False),  # AND across selectors
    ],
)
def test_selector_matrix(selector, value, expected):
    rule = {"rule_id": "r", "effect": "deny", **selector}
    o = effect_of([rule], "allow", **value)
    assert (o.effect == Effect.DENY) is expected
    assert (o.rule_id == "r") is expected


def test_obligation_max_classification():
    rules = [{"rule_id": "r", "effect": "allow", "obligations": {"max_classification": "internal"}}]
    ok = effect_of(rules, objects=[{"kind": "chunk", "classification": "internal"}])
    assert ok.effect == Effect.ALLOW
    ok = effect_of(rules, objects=[{"kind": "chunk", "classification": "public"}])
    assert ok.effect == Effect.ALLOW
    bad = effect_of(rules, objects=[{"kind": "chunk", "classification": "confidential"}])
    assert bad.effect == Effect.DENY and bad.rule_id == "r" and bad.reasons == (ReasonCode.POLICY_DENIED,)
    mixed = effect_of(
        rules,
        objects=[{"kind": "chunk", "classification": "public"}, {"kind": "chunk", "classification": "restricted"}],
    )
    assert mixed.effect == Effect.DENY
    assert [p.effect for p in mixed.per_object] == [Effect.ALLOW, Effect.DENY]


def test_obligation_require_fresh_lineage_recorded():
    rules = [{"rule_id": "r", "effect": "allow", "obligations": {"require_fresh_lineage": True}}]
    assert effect_of(rules).require_fresh_lineage is True
    assert effect_of([{"rule_id": "r", "effect": "allow"}]).require_fresh_lineage is False


def test_no_padding_bypass_per_object_and_tool():
    # A deny rule scoped to "memory" must still fire when a benign "chunk" is added to the request.
    rules = [{"rule_id": "d", "effect": "deny", "resources": {"kinds": ["memory"]}}]
    o = effect_of(rules, "allow", objects=[{"kind": "chunk", "classification": "internal"},
                                          {"kind": "memory", "classification": "internal"}])
    assert o.effect == Effect.DENY
    # Same for tools.
    rules = [{"rule_id": "d", "effect": "deny", "resources": {"tools": ["shell"]}}]
    o = effect_of(rules, "allow", tools=["search", "shell"])
    assert o.effect == Effect.DENY and o.rule_id == "d"
    # An earlier allow scoped to a benign tool must not shadow the deny for the dangerous tool.
    rules = [{"rule_id": "a", "effect": "allow", "resources": {"tools": ["search"]}}, *rules]
    assert effect_of(rules, "allow", tools=["search", "shell"]).effect == Effect.DENY


def test_worst_effect_aggregation_and_tie_rule_id():
    rules = [
        {"rule_id": "hr", "effect": "human_review", "resources": {"kinds": ["memory"]}},
        {"rule_id": "d", "effect": "deny", "resources": {"kinds": ["summary"]}},
    ]
    o = effect_of(rules, "allow", objects=[{"kind": "memory", "classification": "public"},
                                          {"kind": "summary", "classification": "public"}])
    assert o.effect == Effect.DENY and o.rule_id == "d"
    o = effect_of(rules, "allow", objects=[{"kind": "memory", "classification": "public"}])
    assert o.effect == Effect.HUMAN_REVIEW and o.reasons == (ReasonCode.POLICY_HUMAN_REVIEW,)


def test_evaluation_is_deterministic_and_pure():
    d = mkdoc([{"rule_id": "r", "effect": "human_review", "subjects": {"principals": ["*"]}}])
    c = ctx()
    assert evaluate_policy(d, c) == evaluate_policy(d, c) == evaluate_policy(d, dict(c))


def test_unresolved_object_never_matches_resource_selectors():
    d = mkdoc([{"rule_id": "d", "effect": "deny", "resources": {"kinds": ["*"]}}], "allow")
    o = evaluate_policy(d, ctx(objects=[{"kind": None, "classification": None}]))
    assert o.effect == Effect.ALLOW


# ----------------------------------------------------------------------------- store


def test_install_monotonic_and_activate_swap(session):
    PolicyStore.install(session, mkdoc(version=1))
    PolicyStore.install(session, mkdoc(version=2))
    with pytest.raises(PolicyError):
        PolicyStore.install(session, mkdoc(version=2))
    with pytest.raises(PolicyError):
        PolicyStore.install(session, mkdoc(version=1))
    PolicyStore.install(session, mkdoc(version=1, policy_id="other"))  # independent counter per policy_id
    session.commit()
    assert PolicyStore.get_active(session, TENANT) is None
    PolicyStore.activate(session, TENANT, "pol", 1, actor="root")
    PolicyStore.activate(session, TENANT, "pol", 2, actor="root")
    session.commit()
    active = PolicyStore.get_active(session, TENANT)
    assert active is not None and active.version == 2
    flags = session.scalars(select(PolicyDocumentRow.active).where(PolicyDocumentRow.tenant_id == TENANT)).all()
    assert sum(flags) == 1
    # roll back to an older installed version, and across policy ids
    PolicyStore.activate(session, TENANT, "pol", 1, actor="root")
    assert PolicyStore.get_active(session, TENANT).version == 1  # type: ignore[union-attr]
    PolicyStore.activate(session, TENANT, "other", 1, actor="root")
    session.commit()
    assert PolicyStore.get_active(session, TENANT).policy_id == "other"  # type: ignore[union-attr]
    assert sum(session.scalars(select(PolicyDocumentRow.active)).all()) == 1
    assert PolicyStore.list_versions(session, TENANT, "pol") == [("pol", 1, False), ("pol", 2, False)]


def test_activate_unknown_leaves_active_untouched(session):
    PolicyStore.install(session, mkdoc(version=1))
    PolicyStore.activate(session, TENANT, "pol", 1, actor="root")
    session.commit()
    with pytest.raises(PolicyError):
        PolicyStore.activate(session, TENANT, "pol", 9, actor="root")
    session.rollback()
    assert PolicyStore.get_active(session, TENANT).version == 1  # type: ignore[union-attr]


def test_activate_swap_rolls_back_with_failed_audit(session, monkeypatch):
    PolicyStore.install(session, mkdoc(version=1))
    PolicyStore.install(session, mkdoc(version=2))
    PolicyStore.activate(session, TENANT, "pol", 1, actor="root")
    session.commit()

    from ales_core import policy as pol

    def boom(*a, **k):
        raise RuntimeError("audit down")

    monkeypatch.setattr(pol.audit, "append", boom)
    with pytest.raises(RuntimeError):
        PolicyStore.activate(session, TENANT, "pol", 2, actor="root")
    session.rollback()
    assert PolicyStore.get_active(session, TENANT).version == 1  # type: ignore[union-attr]


def test_activation_is_audited_with_actor(session):
    PolicyStore.install(session, mkdoc(version=1))
    PolicyStore.activate(session, TENANT, "pol", 1, actor="root-admin")
    session.commit()
    rows = session.scalars(select(AuditLog).where(AuditLog.action == "policy.activate")).all()
    assert len(rows) == 1 and rows[0].actor == "root-admin"
    assert rows[0].detail["policy_id"] == "pol" and rows[0].detail["version"] == 1
    assert verify_chain(session)[0]


def test_tenants_are_isolated(session):
    PolicyStore.install(session, mkdoc(version=1, tenant="t1"))
    PolicyStore.install(session, mkdoc(version=1, tenant="t2"))
    PolicyStore.activate(session, "t1", "pol", 1, actor="a")
    session.commit()
    assert PolicyStore.get_active(session, "t1") is not None
    assert PolicyStore.get_active(session, "t2") is None
    with pytest.raises(PolicyError):
        PolicyStore.activate(session, "t3", "pol", 1, actor="a")


# ----------------------------------------------------------------------------- restrict-only property

_counter = itertools.count(1)


def _build_world():
    eng = create_engine("sqlite:///:memory:", poolclass=StaticPool, connect_args={"check_same_thread": False})
    create_all(eng)
    s = Session(eng)
    g = GraphStore(s)
    ids: list[str] = []
    for cls, trust in (("public", "verified"), ("internal", "verified"), ("restricted", "verified"),
                       ("confidential", "untrusted")):
        src = make_env("source", classification=cls, trust=trust)
        chunk = make_env("chunk", [(src.context_id, "v1")], classification=cls, trust=trust)
        g.register_source(src)
        g.register_derivation(chunk)
        ids.append(chunk.context_id)
    revoked = make_env("source", classification="internal")
    g.register_source(revoked)
    ids.append(revoked.context_id)
    q = make_env("source", classification="public")
    g.register_source(q)
    ids.append(q.context_id)
    s.commit()
    RevocationEngine().accept(
        s,
        RevocationEvent(event_id=str(uuid.uuid4()), tenant_id=TENANT, source_id=revoked.context_id,
                        reason="deleted", effective_at=NOW - timedelta(days=1)),
        now=NOW,
    )
    RevocationEngine().accept(
        s,
        RevocationEvent(event_id=str(uuid.uuid4()), tenant_id=TENANT, source_id=q.context_id,
                        reason="compromised", effective_at=NOW - timedelta(days=1)),
        now=NOW,
    )
    ids.append(str(uuid.uuid4()))  # unknown object
    return eng, s, ids


_sel = st.one_of(st.none(), st.lists(st.sampled_from(["alice", "bob", "*", "chunk", "source", "qa", "x"]),
                                      min_size=1, max_size=3))
_rule = st.fixed_dictionaries(
    {
        "effect": st.sampled_from(["allow", "deny", "human_review"]),
        "subjects": st.one_of(st.none(), st.fixed_dictionaries({"principals": _sel, "agents": _sel})),
        "resources": st.one_of(
            st.none(),
            st.fixed_dictionaries({
                "kinds": _sel,
                "classifications": st.one_of(st.none(), st.lists(st.sampled_from(["public", "internal", "restricted", "*"]),
                                                                 min_size=1, max_size=2)),
                "tools": _sel,
            }),
        ),
        "purposes": _sel,
        "risk": st.sampled_from([None, "low", "medium", "high"]),
        "obligations": st.one_of(
            st.none(),
            st.fixed_dictionaries({
                "max_classification": st.sampled_from([None, "public", "internal", "confidential", "restricted"]),
                "require_fresh_lineage": st.booleans(),
            }),
        ),
    }
)


def _clean(d):
    if isinstance(d, dict):
        return {k: _clean(v) for k, v in d.items() if v is not None}
    return d


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    rules=st.lists(_rule, max_size=5),
    default=st.sampled_from(["allow", "deny", "human_review"]),
    picks=st.lists(st.integers(min_value=0, max_value=100), min_size=1, max_size=4),
    principal=st.sampled_from(["alice", "bob"]),
    tools=st.lists(st.sampled_from(["search", "shell"]), max_size=2),
    risk=st.sampled_from([None, "low", "high"]),
)
def test_policy_only_restricts(rules, default, picks, principal, tools, risk):
    eng, s, ids = _build_world()
    try:
        raw = [{**_clean(r), "rule_id": f"r{i}"} for i, r in enumerate(rules)]
        refs = [ObjectRef(context_id=ids[p % len(ids)]) for p in picks]
        request = AuthorizeRequest(tenant_id=TENANT, principal=Principal(type="user", id=principal),
                                   purpose="qa", objects=refs, tools=tools, risk=risk)
        base = authorize(s, request, NOW)
        doc = PolicyDocument.model_validate(
            {"policy_id": f"p{next(_counter)}", "tenant_id": TENANT, "version": 1, "rules": raw,
             "default_action": default, "created_by": "t"}
        )
        PolicyStore.install(s, doc)
        PolicyStore.activate(s, TENANT, doc.policy_id, 1, actor="t")
        s.commit()
        with_policy = authorize(s, request, NOW)
        assert with_policy.policy_version == f"{doc.policy_id}@1"
        assert DECISION_SEVERITY[with_policy.decision] >= DECISION_SEVERITY[base.decision]
        for b, w in zip(base.objects, with_policy.objects, strict=True):
            assert DECISION_SEVERITY[w.decision] >= DECISION_SEVERITY[b.decision]
            if b.decision in (Decision.DENY, Decision.QUARANTINE):
                assert w.decision == b.decision and w.reason == b.reason  # lineage deny/quarantine stand
            if b.decision != w.decision:
                assert w.decision in (Decision.DENY, Decision.HUMAN_REVIEW)
        # determinism: same inputs, same decision/verdicts
        again = authorize(s, request, NOW)
        assert again.decision == with_policy.decision
        assert [o.decision for o in again.objects] == [o.decision for o in with_policy.objects]
    finally:
        s.close()
        eng.dispose()


def test_policy_cannot_override_lineage_deny(session, chain):
    PolicyStore.install(session, mkdoc([{"rule_id": "all", "effect": "allow"}], "allow"))
    PolicyStore.activate(session, TENANT, "pol", 1, actor="a")
    session.commit()
    RevocationEngine().accept(
        session,
        RevocationEvent(event_id=str(uuid.uuid4()), tenant_id=TENANT, source_id=chain["source"].context_id,
                        reason="deleted", effective_at=NOW - timedelta(days=1)),
        now=NOW,
    )
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.ANCESTOR_DELETED]
