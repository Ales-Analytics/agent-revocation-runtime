from __future__ import annotations

from datetime import timedelta

import pytest
from ales_core import (
    AuthorizeRequest,
    Decision,
    DelegationStore,
    ObjectRef,
    Principal,
    ReasonCode,
    WorkloadError,
    WorkloadRegistry,
    authorize,
    authorize_ex,
    authorize_handoff,
    check_capability,
    verify_chain,
)
from ales_core.db import AuditLog
from core_fixtures import NOW, TENANT, req
from sqlalchemy import select

A = {"actor": "admin"}


def reg(session, wid, kind="agent", caps=None, tenant=TENANT):
    return WorkloadRegistry.register(session, tenant, wid, kind, wid.title(), caps or [], **A)


def deleg(session, f, t, **kw):
    return DelegationStore.create(session, TENANT, f, t, actor="admin", **kw)


@pytest.fixture
def two(session):
    reg(session, "sales", caps=["tool:search"])
    reg(session, "support", caps=["handoff:support"])
    session.commit()


def test_register_get_list_and_duplicates(session):
    row = reg(session, "a1", "agent", ["tool:b", "tool:a", "tool:a"])
    assert row.capabilities == ["tool:a", "tool:b"] and row.status == "active"
    assert WorkloadRegistry.get(session, TENANT, "a1") is row
    assert WorkloadRegistry.get(session, "other", "a1") is None
    assert not WorkloadRegistry.has_any(session, "other") and WorkloadRegistry.has_any(session, TENANT)
    with pytest.raises(WorkloadError):
        reg(session, "a1")
    with pytest.raises(ValueError):
        WorkloadRegistry.register(session, TENANT, "x", "robot", "x", [], **A)
    reg(session, "a1", tenant="other")  # same id in another tenant is fine
    assert [w.workload_id for w in WorkloadRegistry.list_all(session, TENANT)] == ["a1"]


def test_capability_checks(session):
    reg(session, "a1", caps=["tool:search", "plain"])
    session.commit()
    assert check_capability(session, TENANT, "a1", "tool:search")
    assert check_capability(session, TENANT, "a1", "search")  # tool: prefix form
    assert check_capability(session, TENANT, "a1", "plain")
    assert not check_capability(session, TENANT, "a1", "shell")
    assert not check_capability(session, TENANT, "unknown", "tool:search")
    assert not check_capability(session, "other", "a1", "tool:search")
    WorkloadRegistry.set_status(session, TENANT, "a1", "suspended", **A)
    assert not check_capability(session, TENANT, "a1", "tool:search")
    WorkloadRegistry.set_status(session, TENANT, "a1", "active", **A)
    assert check_capability(session, TENANT, "a1", "tool:search")
    WorkloadRegistry.set_capabilities(session, TENANT, "a1", [], **A)
    assert not check_capability(session, TENANT, "a1", "tool:search")


def test_set_status_unknown_workload_and_bad_status(session):
    with pytest.raises(WorkloadError):
        WorkloadRegistry.set_status(session, TENANT, "nope", "suspended", **A)
    reg(session, "a1")
    with pytest.raises(ValueError):
        WorkloadRegistry.set_status(session, TENANT, "a1", "banished", **A)


def test_handoff_allow(session, two):
    deleg(session, "sales", "support")
    session.commit()
    d, r = authorize_handoff(session, TENANT, "sales", "support", "qa", NOW)
    assert d == Decision.ALLOW and r == [ReasonCode.OK]


def test_handoff_missing_and_directional(session, two):
    d, r = authorize_handoff(session, TENANT, "sales", "support", "qa", NOW)
    assert d == Decision.DENY and r == [ReasonCode.DELEGATION_MISSING]
    deleg(session, "support", "sales")  # reverse direction does not help
    d, r = authorize_handoff(session, TENANT, "sales", "support", "qa", NOW)
    assert d == Decision.DENY and r == [ReasonCode.DELEGATION_MISSING]


def test_handoff_purpose_scoping(session, two):
    deleg(session, "sales", "support", purposes=["support", "billing"])
    assert authorize_handoff(session, TENANT, "sales", "support", "billing", NOW)[0] == Decision.ALLOW
    d, r = authorize_handoff(session, TENANT, "sales", "support", "marketing", NOW)
    assert d == Decision.DENY and r == [ReasonCode.DELEGATION_MISSING]


def test_handoff_expired_and_check_states(session, two):
    exp = NOW + timedelta(hours=1)
    deleg(session, "sales", "support", expires_at=exp)
    assert DelegationStore.check(session, TENANT, "sales", "support", "qa", NOW) == "ok"
    assert DelegationStore.check(session, TENANT, "sales", "support", "qa", exp - timedelta(seconds=1)) == "ok"
    assert DelegationStore.check(session, TENANT, "sales", "support", "qa", exp) == "expired"  # inclusive
    d, r = authorize_handoff(session, TENANT, "sales", "support", "qa", exp + timedelta(days=1))
    assert d == Decision.DENY and r == [ReasonCode.DELEGATION_MISSING]


def test_handoff_revoked(session, two):
    d1 = deleg(session, "sales", "support")
    assert authorize_handoff(session, TENANT, "sales", "support", "qa", NOW)[0] == Decision.ALLOW
    DelegationStore.revoke(session, TENANT, d1.delegation_id, actor="admin")
    assert DelegationStore.check(session, TENANT, "sales", "support", "qa", NOW) == "revoked"
    assert authorize_handoff(session, TENANT, "sales", "support", "qa", NOW)[0] == Decision.DENY
    # a second, valid delegation restores access
    deleg(session, "sales", "support")
    assert DelegationStore.check(session, TENANT, "sales", "support", "qa", NOW) == "ok"
    with pytest.raises(WorkloadError):
        DelegationStore.revoke(session, TENANT, "nope", actor="admin")


def test_handoff_suspended_or_unknown_workload(session, two):
    deleg(session, "sales", "support")
    WorkloadRegistry.set_status(session, TENANT, "support", "suspended", **A)
    d, r = authorize_handoff(session, TENANT, "sales", "support", "qa", NOW)
    assert d == Decision.DENY and r == [ReasonCode.WORKLOAD_SUSPENDED]
    WorkloadRegistry.set_status(session, TENANT, "support", "active", **A)
    WorkloadRegistry.set_status(session, TENANT, "sales", "suspended", **A)
    assert authorize_handoff(session, TENANT, "sales", "support", "qa", NOW)[1] == [ReasonCode.WORKLOAD_SUSPENDED]
    d, r = authorize_handoff(session, TENANT, "ghost", "support", "qa", NOW)
    assert d == Decision.DENY and ReasonCode.WORKLOAD_SUSPENDED in r and ReasonCode.DELEGATION_MISSING in r


def test_delegation_requires_registered_workloads_and_valid_purposes(session, two):
    with pytest.raises(WorkloadError):
        deleg(session, "sales", "ghost")
    with pytest.raises(WorkloadError):
        deleg(session, "sales", "support", purposes=[])


def test_delegation_tenant_isolation(session, two):
    deleg(session, "sales", "support")
    reg(session, "sales", tenant="t2")
    reg(session, "support", tenant="t2")
    assert authorize_handoff(session, "t2", "sales", "support", "qa", NOW)[0] == Decision.DENY


def test_grants(session, two):
    assert not WorkloadRegistry.can_act_as(session, TENANT, "alice", "sales")
    WorkloadRegistry.grant(session, TENANT, "alice", "sales", actor="admin")
    WorkloadRegistry.grant(session, TENANT, "alice", "sales", actor="admin")  # idempotent
    assert WorkloadRegistry.can_act_as(session, TENANT, "alice", "sales")
    assert not WorkloadRegistry.can_act_as(session, TENANT, "alice", "support")
    assert not WorkloadRegistry.can_act_as(session, TENANT, "bob", "sales")
    assert len(WorkloadRegistry.list_grants(session, TENANT, "alice")) == 1
    WorkloadRegistry.set_status(session, TENANT, "sales", "suspended", **A)
    assert not WorkloadRegistry.can_act_as(session, TENANT, "alice", "sales")
    WorkloadRegistry.set_status(session, TENANT, "sales", "active", **A)
    assert WorkloadRegistry.revoke_grant(session, TENANT, "alice", "sales", actor="admin")
    assert not WorkloadRegistry.can_act_as(session, TENANT, "alice", "sales")
    assert not WorkloadRegistry.revoke_grant(session, TENANT, "alice", "sales", actor="admin")
    with pytest.raises(WorkloadError):
        WorkloadRegistry.grant(session, TENANT, "alice", "ghost", actor="admin")


def test_mutations_are_audited(session):
    reg(session, "a", caps=["x"])
    reg(session, "b")
    WorkloadRegistry.set_status(session, TENANT, "a", "suspended", actor="ops")
    d = DelegationStore.create(session, TENANT, "a", "b", actor="ops")
    DelegationStore.revoke(session, TENANT, d.delegation_id, actor="sec")
    session.commit()
    rows = session.scalars(select(AuditLog).order_by(AuditLog.seq)).all()
    assert [(r.action, r.actor) for r in rows] == [
        ("workload.register", "admin"),
        ("workload.register", "admin"),
        ("workload.status", "ops"),
        ("delegation.create", "ops"),
        ("delegation.revoke", "sec"),
    ]
    assert verify_chain(session)[0]


# ----------------------------------------------------------------------------- resolver gate


def areq(chain, agent, tools=(), tenant=TENANT):
    return AuthorizeRequest(
        tenant_id=tenant,
        principal=Principal(type="agent", id="alice"),
        purpose="qa",
        agent_id=agent,
        objects=[ObjectRef(context_id=chain["memory"].context_id)],
        tools=list(tools),
    )


def test_gate_is_opt_in_no_workloads_keeps_old_behaviour(session, chain):
    r = authorize(session, areq(chain, "anything", ["shell"]), NOW)
    assert r.decision == Decision.ALLOW and r.reason == [ReasonCode.OK]
    # Other tenants' workloads do not switch the gate on for this tenant.
    reg(session, "a1", tenant="other-tenant")
    session.commit()
    assert authorize(session, areq(chain, "anything", ["shell"]), NOW).decision == Decision.ALLOW


def test_gate_not_applied_without_agent_id(session, chain):
    reg(session, "a1")
    session.commit()
    r = authorize(session, req(chain["memory"].context_id), NOW)
    assert r.decision == Decision.ALLOW


def test_gate_unknown_agent_denied(session, chain):
    reg(session, "a1", caps=["tool:search"])
    session.commit()
    r = authorize(session, areq(chain, "ghost"), NOW)
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.WORKLOAD_SUSPENDED]
    assert r.objects[0].decision == Decision.DENY and r.objects[0].reason == [ReasonCode.WORKLOAD_SUSPENDED]


def test_gate_suspended_agent_denied_then_restored(session, chain):
    reg(session, "a1")
    WorkloadRegistry.set_status(session, TENANT, "a1", "suspended", **A)
    session.commit()
    assert authorize(session, areq(chain, "a1"), NOW).reason == [ReasonCode.WORKLOAD_SUSPENDED]
    WorkloadRegistry.set_status(session, TENANT, "a1", "active", **A)
    session.commit()
    assert authorize(session, areq(chain, "a1"), NOW).decision == Decision.ALLOW


def test_gate_capability_missing(session, chain):
    reg(session, "a1", caps=["tool:search"])
    session.commit()
    assert authorize(session, areq(chain, "a1", ["search"]), NOW).decision == Decision.ALLOW
    assert authorize(session, areq(chain, "a1", ["tool:search"]), NOW).decision == Decision.ALLOW
    r = authorize(session, areq(chain, "a1", ["search", "shell"]), NOW)
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.CAPABILITY_MISSING]
    assert authorize(session, areq(chain, "a1"), NOW).decision == Decision.ALLOW  # no tools requested


def test_gate_keeps_lineage_reasons_and_quarantine(session, chain):
    from ales_core import RevocationEngine, RevocationEvent

    reg(session, "a1")
    session.commit()
    RevocationEngine().accept(
        session,
        RevocationEvent(event_id="11111111-1111-4111-8111-111111111111", tenant_id=TENANT,
                        source_id=chain["source"].context_id, reason="poisoned", effective_at=NOW - timedelta(days=1)),
        now=NOW,
    )
    r = authorize(session, areq(chain, "ghost"), NOW)
    assert r.decision == Decision.QUARANTINE  # lineage verdicts stand; the gate never loosens
    r = authorize(session, areq(chain, "a1"), NOW)
    assert r.decision == Decision.QUARANTINE


# ----------------------------------------------------------------------------- grants gate + modes
def _ap(chain, agent="a1", principal="alice", tools=()):
    r = areq(chain, agent, tools)
    return r.model_copy(update={"principal": Principal(type="user", id=principal)})


def test_grants_gate_is_second_opt_in(session, chain):
    reg(session, "a1")
    session.commit()
    assert authorize(session, _ap(chain), NOW).decision == Decision.ALLOW  # workloads, no grants: unchanged
    WorkloadRegistry.grant(session, TENANT, "alice", "a1", actor="admin")
    session.commit()
    assert not WorkloadRegistry.has_any_grants(session, "other-tenant")
    assert authorize(session, _ap(chain), NOW).decision == Decision.ALLOW  # alice holds the grant
    out = authorize_ex(session, _ap(chain, principal="bob"), NOW)
    assert out.response.decision == Decision.DENY and out.response.reason == [ReasonCode.PRINCIPAL_NOT_IN_SCOPE]
    assert out.grant_missing and out.audit_extra()["grant_missing"] is True
    assert "grant_missing" not in authorize_ex(session, _ap(chain), NOW).audit_extra()
    # a request without agent_id is untouched by the grants gate
    assert authorize(session, req(chain["memory"].context_id), NOW).decision == Decision.ALLOW


def test_revoked_grant_denies_and_last_revoke_reopens_gate(session, chain):
    reg(session, "a1")
    WorkloadRegistry.grant(session, TENANT, "alice", "a1", actor="admin")
    WorkloadRegistry.grant(session, TENANT, "carol", "a1", actor="admin")
    session.commit()
    assert authorize(session, _ap(chain), NOW).decision == Decision.ALLOW
    WorkloadRegistry.revoke_grant(session, TENANT, "alice", "a1", actor="admin")
    session.commit()
    assert authorize(session, _ap(chain), NOW).reason == [ReasonCode.PRINCIPAL_NOT_IN_SCOPE]
    WorkloadRegistry.revoke_grant(session, TENANT, "carol", "a1", actor="admin")
    session.commit()  # no grants left: gate off again (documented)
    assert authorize(session, _ap(chain), NOW).decision == Decision.ALLOW


def test_require_grants_pins_the_gate_with_zero_grant_rows(session, chain):
    reg(session, "a1")
    session.commit()
    assert not WorkloadRegistry.has_any_grants(session, TENANT)
    # default: workloads but no grants -> unchanged behaviour
    assert authorize(session, _ap(chain), NOW).decision == Decision.ALLOW
    # pinned: no grant => denied even though the tenant has zero grant rows
    out = authorize_ex(session, _ap(chain), NOW, require_grants=True)
    assert out.response.decision == Decision.DENY and out.response.reason == [ReasonCode.PRINCIPAL_NOT_IN_SCOPE]
    assert out.grant_missing and out.audit_extra()["grant_missing"] is True
    assert authorize(session, _ap(chain), NOW, require_grants=True).decision == Decision.DENY
    WorkloadRegistry.grant(session, TENANT, "alice", "a1", actor="admin")
    session.commit()
    assert authorize(session, _ap(chain), NOW, require_grants=True).decision == Decision.ALLOW
    # deleting the last grant can no longer switch the gate off
    WorkloadRegistry.revoke_grant(session, TENANT, "alice", "a1", actor="admin")
    session.commit()
    assert not WorkloadRegistry.has_any_grants(session, TENANT)
    assert authorize(session, _ap(chain), NOW, require_grants=True).decision == Decision.DENY
    # not applied without agent_id, or when the workload gate itself is off
    assert authorize(session, req(chain["memory"].context_id), NOW, require_grants=True).decision == Decision.ALLOW
    assert authorize(session, _ap(chain), NOW, enforce_workloads="off", require_grants=True).decision == Decision.ALLOW
    # strict + require_grants: unknown agent is still WORKLOAD_SUSPENDED (earlier gate wins)
    assert authorize(session, _ap(chain, agent="ghost"), NOW, enforce_workloads="strict",
                     require_grants=True).reason == [ReasonCode.WORKLOAD_SUSPENDED]


def test_grants_gate_other_denials_take_precedence(session, chain):
    reg(session, "a1", caps=["tool:search"])
    WorkloadRegistry.grant(session, TENANT, "carol", "a1", actor="admin")
    session.commit()
    r = authorize(session, _ap(chain, tools=["shell"]), NOW)
    assert r.reason == [ReasonCode.CAPABILITY_MISSING]
    assert authorize(session, _ap(chain, agent="ghost"), NOW).reason == [ReasonCode.WORKLOAD_SUSPENDED]


def test_enforcement_modes(session, chain):
    # auto (default): no workloads registered -> agent_id is an unverified label
    assert authorize(session, areq(chain, "ghost"), NOW).decision == Decision.ALLOW
    assert authorize(session, areq(chain, "ghost"), NOW, enforce_workloads="auto").decision == Decision.ALLOW
    # strict: unknown agent denied even with zero workloads
    out = authorize_ex(session, areq(chain, "ghost"), NOW, enforce_workloads="strict")
    assert out.response.decision == Decision.DENY and out.response.reason == [ReasonCode.WORKLOAD_SUSPENDED]
    assert out.workload_gate and out.audit_extra()["workload_enforcement"] == "strict"
    # strict still ignores requests without agent_id
    assert authorize(session, req(chain["memory"].context_id), NOW, enforce_workloads="strict").decision == Decision.ALLOW
    # off: gate disabled even for tenants with workloads / grants
    reg(session, "a1", caps=["tool:search"])
    WorkloadRegistry.grant(session, TENANT, "carol", "a1", actor="admin")
    session.commit()
    assert authorize(session, areq(chain, "ghost"), NOW).decision == Decision.DENY  # auto now enforces
    off = authorize_ex(session, areq(chain, "ghost", ["shell"]), NOW, enforce_workloads="off")
    assert off.response.decision == Decision.ALLOW and not off.workload_gate
    assert authorize(session, _ap(chain, principal="bob"), NOW, enforce_workloads="off").decision == Decision.ALLOW
    assert authorize(session, _ap(chain, principal="bob"), NOW, enforce_workloads="strict").decision == Decision.DENY
    with pytest.raises(ValueError):
        authorize(session, areq(chain, "a1"), NOW, enforce_workloads="lax")  # type: ignore[arg-type]
