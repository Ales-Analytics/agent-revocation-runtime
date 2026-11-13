from __future__ import annotations

from datetime import timedelta

import pytest
from ales_core import (
    ApprovalError,
    ApprovalStore,
    AuthorizeRequest,
    Decision,
    ObjectRef,
    PolicyDocument,
    PolicyStore,
    Principal,
    ReasonCode,
    authorize,
    authorize_ex,
    fingerprint,
    record_decision,
    verify_chain,
)
from ales_core.db import ApprovalRow, AuditLog
from core_fixtures import NOW, TENANT
from sqlalchemy import select

P = Principal(type="user", id="alice")


def test_fingerprint_stability_and_sensitivity():
    objs = [("c1", "v1"), ("c2", "v1")]
    f = fingerprint(P, "qa", objs, "pol@1")
    assert len(f) == 64 and int(f, 16) >= 0
    assert f == fingerprint(P, "qa", objs, "pol@1")
    assert f == fingerprint({"type": "user", "id": "alice"}, "qa", list(reversed(objs)), "pol@1")  # order-free
    assert f == fingerprint(P, "qa", objs + objs, "pol@1")  # duplicate-free
    assert f == fingerprint(P, "qa", [{"context_id": "c1", "version": "v1"}, ObjRef("c2", "v1")], "pol@1")
    assert f != fingerprint(Principal(type="user", id="bob"), "qa", objs, "pol@1")
    assert f != fingerprint(Principal(type="agent", id="alice"), "qa", objs, "pol@1")
    assert f != fingerprint(P, "billing", objs, "pol@1")
    assert f != fingerprint(P, "qa", objs[:1], "pol@1")
    assert f != fingerprint(P, "qa", [("c1", "v1"), ("c2", "v2")], "pol@1")
    assert f != fingerprint(P, "qa", objs, "pol@2")
    # Pinned golden value: any change to the canonical form must be a deliberate, reviewed change.
    assert f == "e40000a12940ec89c4bb1605832208acabdf0bb1fd5a6d3b1808f7df29b11770"  # golden: canonical form is frozen


def ObjRef(c, v):
    return ObjectRef(context_id=c, version=v)


def test_ensure_pending_idempotent(session):
    a = ApprovalStore.ensure_pending(session, TENANT, "f" * 64, {"purpose": "qa"}, now=NOW)
    b = ApprovalStore.ensure_pending(session, TENANT, "f" * 64, {"purpose": "qa"}, now=NOW)
    assert a.approval_id == b.approval_id and a.state == "pending"
    c = ApprovalStore.ensure_pending(session, TENANT, "e" * 64, {}, now=NOW)
    assert c.approval_id != a.approval_id
    other = ApprovalStore.ensure_pending(session, "t2", "f" * 64, {}, now=NOW)
    assert other.approval_id != a.approval_id  # tenant scoped
    assert session.scalars(select(ApprovalRow).where(ApprovalRow.tenant_id == TENANT)).all().__len__() == 2


def test_status_lifecycle_approve_expire_cycle(session):
    fp = "a" * 64
    assert ApprovalStore.status(session, TENANT, fp, NOW) == "none"
    ap = ApprovalStore.ensure_pending(session, TENANT, fp, {}, now=NOW)
    assert ApprovalStore.status(session, TENANT, fp, NOW) == "pending"
    ApprovalStore.decide(session, TENANT, ap.approval_id, True, "boss", 600, now=NOW)
    assert ApprovalStore.status(session, TENANT, fp, NOW + timedelta(seconds=599)) == "approved"
    assert ApprovalStore.status(session, TENANT, fp, NOW + timedelta(seconds=600)) == "none"  # expired
    # idempotent while live
    assert ApprovalStore.ensure_pending(session, TENANT, fp, {}, now=NOW + timedelta(seconds=10)).approval_id == ap.approval_id
    # after expiry a fresh pending record is created
    again = ApprovalStore.ensure_pending(session, TENANT, fp, {}, now=NOW + timedelta(seconds=700))
    assert again.approval_id != ap.approval_id
    assert ApprovalStore.status(session, TENANT, fp, NOW + timedelta(seconds=700)) == "pending"
    assert ApprovalStore.mark_expired(session, TENANT, NOW + timedelta(seconds=700)) == 1
    assert session.scalars(select(ApprovalRow.state).where(ApprovalRow.approval_id == ap.approval_id)).one() == "expired"


def test_decide_denied_and_errors(session):
    fp = "b" * 64
    ap = ApprovalStore.ensure_pending(session, TENANT, fp, {}, now=NOW)
    with pytest.raises(ApprovalError):
        ApprovalStore.decide(session, TENANT, ap.approval_id, True, "boss", 0, now=NOW)
    with pytest.raises(ApprovalError):
        ApprovalStore.decide(session, TENANT, ap.approval_id, True, "", 60, now=NOW)
    with pytest.raises(ApprovalError):
        ApprovalStore.decide(session, TENANT, "nope", True, "boss", 60, now=NOW)
    with pytest.raises(ApprovalError):  # wrong tenant cannot decide
        ApprovalStore.decide(session, "t2", ap.approval_id, True, "boss", 60, now=NOW)
    ApprovalStore.decide(session, TENANT, ap.approval_id, False, "boss", 60, now=NOW)
    assert ApprovalStore.status(session, TENANT, fp, NOW) == "denied"
    with pytest.raises(ApprovalError):  # no double decision
        ApprovalStore.decide(session, TENANT, ap.approval_id, True, "boss", 60, now=NOW)
    assert ApprovalStore.status(session, TENANT, fp, NOW + timedelta(seconds=61)) == "none"


def test_undated_decision_grants_nothing(session):
    fp = "c" * 64
    ap = ApprovalStore.ensure_pending(session, TENANT, fp, {}, now=NOW)
    ap.state, ap.expires_at = "approved", None  # corrupted/legacy row
    session.flush()
    assert ApprovalStore.status(session, TENANT, fp, NOW) == "none"


def test_decide_audited_without_content(session):
    ap = ApprovalStore.ensure_pending(session, TENANT, "d" * 64, {"purpose": "qa"}, now=NOW)
    ApprovalStore.decide(session, TENANT, ap.approval_id, True, "boss@corp", 60, now=NOW)
    session.commit()
    rows = session.scalars(select(AuditLog).order_by(AuditLog.seq)).all()
    assert [r.action for r in rows] == ["approval.request", "approval.decide"]
    assert rows[1].actor == "boss@corp" and rows[1].detail["approved"] is True
    assert verify_chain(session)[0]


# ----------------------------------------------------------------------------- resolver flow


def _policy(session, rules, default="allow", version=1):
    PolicyStore.install(
        session,
        PolicyDocument.model_validate(
            {"policy_id": "pol", "tenant_id": TENANT, "version": version, "rules": rules,
             "default_action": default, "created_by": "admin"}
        ),
    )
    PolicyStore.activate(session, TENANT, "pol", version, actor="admin")
    session.commit()


def _req(chain, principal="alice", purpose="qa"):
    return AuthorizeRequest(
        tenant_id=TENANT, principal=Principal(type="user", id=principal), purpose=purpose,
        objects=[ObjectRef(context_id=chain["memory"].context_id)],
    )


HR = [{"rule_id": "hr", "effect": "human_review", "subjects": {"principals": ["alice"]}}]


def test_human_review_approve_allow_expire_cycle(session, chain):
    _policy(session, HR)
    r = _req(chain)
    out = authorize_ex(session, r, NOW)
    assert out.response.decision == Decision.HUMAN_REVIEW
    assert out.response.reason == [ReasonCode.POLICY_HUMAN_REVIEW, ReasonCode.APPROVAL_PENDING]
    assert out.response.objects[0].decision == Decision.HUMAN_REVIEW
    assert out.response.policy_version == "pol@1"
    assert out.approval_required and out.policy_rule_id == "hr" and out.fingerprint
    assert out.approval_context is not None
    assert "content" not in str(out.approval_context).lower()
    # resolver is read-only wrt approvals
    assert session.scalars(select(ApprovalRow)).all() == []
    ap = ApprovalStore.ensure_pending(session, TENANT, out.fingerprint, out.approval_context, now=NOW)
    session.commit()
    assert authorize(session, r, NOW).decision == Decision.HUMAN_REVIEW  # still pending

    ApprovalStore.decide(session, TENANT, ap.approval_id, True, "boss", 300, now=NOW)
    session.commit()
    ok = authorize_ex(session, r, NOW + timedelta(seconds=10))
    assert ok.response.decision == Decision.ALLOW and ok.response.reason == [ReasonCode.OK]
    assert ok.approval_id == ap.approval_id and not ok.approval_required
    assert ok.audit_extra()["approval_id"] == ap.approval_id


def test_approval_does_not_cover_other_fingerprint(session, chain):
    _policy(session, HR)
    r = _req(chain)
    out = authorize_ex(session, r, NOW)
    ap = ApprovalStore.ensure_pending(session, TENANT, out.fingerprint, out.approval_context, now=NOW)
    ApprovalStore.decide(session, TENANT, ap.approval_id, True, "boss", 300, now=NOW)
    session.commit()
    other = authorize(session, _req(chain, purpose="other"), NOW)
    assert other.decision == Decision.HUMAN_REVIEW  # same rule, different purpose => new fingerprint
    assert authorize(session, r, NOW).decision == Decision.ALLOW


def test_approval_expires_back_to_human_review(session, chain):
    _policy(session, HR)
    r = _req(chain)
    out = authorize_ex(session, r, NOW)
    ap = ApprovalStore.ensure_pending(session, TENANT, out.fingerprint, out.approval_context, now=NOW)
    ApprovalStore.decide(session, TENANT, ap.approval_id, True, "boss", 300, now=NOW)
    session.commit()
    assert authorize(session, r, NOW + timedelta(seconds=299)).decision == Decision.ALLOW
    late = authorize_ex(session, r, NOW + timedelta(seconds=300))
    assert late.response.decision == Decision.HUMAN_REVIEW and late.approval_required


def test_denied_approval_denies(session, chain):
    _policy(session, HR)
    r = _req(chain)
    out = authorize_ex(session, r, NOW)
    ap = ApprovalStore.ensure_pending(session, TENANT, out.fingerprint, out.approval_context, now=NOW)
    ApprovalStore.decide(session, TENANT, ap.approval_id, False, "boss", 300, now=NOW)
    session.commit()
    d = authorize_ex(session, r, NOW + timedelta(seconds=1))
    assert d.response.decision == Decision.DENY and d.response.reason == [ReasonCode.APPROVAL_DENIED]
    assert not d.approval_required


def test_new_policy_version_invalidates_approval(session, chain):
    _policy(session, HR)
    r = _req(chain)
    out = authorize_ex(session, r, NOW)
    ap = ApprovalStore.ensure_pending(session, TENANT, out.fingerprint, out.approval_context, now=NOW)
    ApprovalStore.decide(session, TENANT, ap.approval_id, True, "boss", 300, now=NOW)
    session.commit()
    assert authorize(session, r, NOW).decision == Decision.ALLOW
    _policy(session, HR, version=2)
    assert authorize(session, r, NOW).decision == Decision.HUMAN_REVIEW  # fingerprint binds policy_version


def test_approval_cannot_override_policy_deny_or_lineage_deny(session, chain):
    _policy(session, [{"rule_id": "d", "effect": "deny"}], default="allow")
    r = authorize(session, _req(chain), NOW)
    assert r.decision == Decision.DENY and r.reason == [ReasonCode.POLICY_DENIED]


def test_audit_record_decision_extra(session, chain):
    _policy(session, HR)
    r = _req(chain)
    out = authorize_ex(session, r, NOW)
    row = record_decision(session, "svc", r, out.response, at=NOW, extra=out.audit_extra())
    assert row.detail["policy"]["policy_rule_id"] == "hr"
    assert row.detail["policy_version"] == "pol@1"
    assert verify_chain(session)[0]


# ------------------------------------------------------------------------- separation of duties
def test_ensure_pending_records_both_requesters(session):
    ap = ApprovalStore.ensure_pending(
        session, TENANT, "1" * 64, {"principal": {"type": "user", "id": "alice"}}, actor="svc-a", now=NOW
    )
    assert (ap.requested_by_principal, ap.requested_actor) == ("alice", "svc-a")  # principal from context
    ap2 = ApprovalStore.ensure_pending(
        session, TENANT, "2" * 64, {}, actor="svc-a", requested_by_principal="bob", now=NOW
    )
    assert (ap2.requested_by_principal, ap2.requested_actor) == ("bob", "svc-a")  # explicit wins


@pytest.mark.parametrize("who", ["alice", "svc-a"])
@pytest.mark.parametrize("approve", [True, False])
def test_decide_refuses_requester_identities(session, who, approve):
    from ales_core import SeparationOfDuties

    ap = ApprovalStore.ensure_pending(session, TENANT, "3" * 64, {}, actor="svc-a", requested_by_principal="alice", now=NOW)
    with pytest.raises(SeparationOfDuties, match="separation of duties: decider matches requester"):
        ApprovalStore.decide(session, TENANT, ap.approval_id, approve, who, 60, now=NOW)
    assert isinstance(SeparationOfDuties(), ApprovalError)
    assert ApprovalStore.status(session, TENANT, "3" * 64, NOW) == "pending"  # refusal changes nothing
    ApprovalStore.decide(session, TENANT, ap.approval_id, approve, "other-admin", 60, now=NOW)


def test_decide_allow_self_escape_hatch(session):
    ap = ApprovalStore.ensure_pending(session, TENANT, "4" * 64, {}, actor="svc-a", requested_by_principal="alice", now=NOW)
    ApprovalStore.decide(session, TENANT, ap.approval_id, True, "alice", 60, now=NOW, allow_self=True)
    assert ApprovalStore.status(session, TENANT, "4" * 64, NOW) == "approved"


def test_legacy_rows_without_requester_are_not_blocked(session):
    ap = ApprovalStore.ensure_pending(session, TENANT, "5" * 64, {}, actor="x", now=NOW)
    ap.requested_by_principal = ap.requested_actor = None  # a pre-0003 row
    session.flush()
    ApprovalStore.decide(session, TENANT, ap.approval_id, True, "anyone", 60, now=NOW)
