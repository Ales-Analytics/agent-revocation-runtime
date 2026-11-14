"""External policy providers (v0.4): models, composition matrix, application to verdicts, approval binding."""

from __future__ import annotations

import itertools
from datetime import timedelta

import pytest
from ales_core import (
    ApprovalStore,
    CallMeta,
    Decision,
    PolicyProviderRequest,
    PolicyProviderResult,
    ProviderConfig,
    ReasonCode,
    ReleaseReceipt,
    apply_composed,
    authorize_ex,
    build_provider_request,
    compose_provider_results,
    needs_provider_call,
    release_reasons,
)
from core_fixtures import NOW, TENANT, make_env, req
from pydantic import ValidationError


def cfg(name: str = "p", required: bool = True, **kw) -> ProviderConfig:
    return ProviderConfig(name=name, url="https://opa.internal/v1/data/x", required=required, **kw)


def res(decision: str, **kw) -> PolicyProviderResult:
    kw.setdefault("provider", "p")
    kw.setdefault("policy_revision", "r1")
    return PolicyProviderResult(decision=decision, **kw)


# ------------------------------------------------------------------------------------------ models
def test_config_rejects_inline_secret_and_bad_url():
    with pytest.raises(ValidationError):
        ProviderConfig(name="a", url="https://x", auth_token_env="Bearer abc def")
    with pytest.raises(ValidationError):
        ProviderConfig(name="a", url="ftp://x")
    with pytest.raises(ValidationError):
        ProviderConfig(name="a", url="https://user:pw@x")
    with pytest.raises(ValidationError):
        ProviderConfig(name="bad name", url="https://x")
    with pytest.raises(ValidationError):
        ProviderConfig(name="a", url="https://x", token="inline")  # extra forbidden
    c = ProviderConfig(name="a", url="https://x")
    assert c.required is True and c.timeout_s == 3.0  # fail closed by default


def test_result_strict_types_and_normalised_instant():
    with pytest.raises(ValidationError):
        PolicyProviderResult.model_validate({"decision": "allow", "provider": "p", "policy_revision": "r"})
    with pytest.raises(ValidationError):
        PolicyProviderResult.model_validate({"decision": True, "provider": "p", "policy_revision": "r"})
    with pytest.raises(ValidationError):  # policy_revision is part of the evidence: required
        PolicyProviderResult.model_validate({"decision": "ALLOW", "provider": "p"})
    with pytest.raises(ValidationError):  # naive instant is not a validity boundary
        res("ALLOW", valid_until="2026-01-01T00:00:00")
    r = res("ALLOW", valid_until="2026-01-01T01:00:00+01:00")
    assert r.valid_until == "2026-01-01T00:00:00.000000Z"
    # unknown extra fields are ignored (engines add diagnostics)
    assert PolicyProviderResult.model_validate(
        {"decision": "ALLOW", "provider": "p", "policy_revision": "r", "diagnostics": {"x": 1}}
    ).decision == "ALLOW"


def test_obligation_bounds():
    with pytest.raises(ValidationError):
        res("ALLOW", obligations=["x"] * 33)
    with pytest.raises(ValidationError):
        res("ALLOW", obligations=[{"k": "v" * 3000}])


# ----------------------------------------------------------------------------- composition matrix
@pytest.mark.parametrize("required", [True, False])
@pytest.mark.parametrize(
    ("answer", "req_expect", "opt_expect"),
    [
        ("ALLOW", (Decision.ALLOW, ReasonCode.OK), (Decision.ALLOW, ReasonCode.OK)),
        ("DENY", (Decision.DENY, ReasonCode.EXTERNAL_POLICY_DENIED), (Decision.DENY, ReasonCode.EXTERNAL_POLICY_DENIED)),
        ("UNKNOWN", (Decision.UNKNOWN, ReasonCode.EXTERNAL_POLICY_UNAVAILABLE), (Decision.ALLOW, ReasonCode.OK)),
        ("HUMAN_REVIEW", (Decision.HUMAN_REVIEW, ReasonCode.POLICY_HUMAN_REVIEW),
         (Decision.HUMAN_REVIEW, ReasonCode.POLICY_HUMAN_REVIEW)),
        (None, (Decision.UNKNOWN, ReasonCode.EXTERNAL_POLICY_UNAVAILABLE), (Decision.ALLOW, ReasonCode.OK)),
    ],
)
def test_single_provider_matrix(required, answer, req_expect, opt_expect):
    result = res(answer) if answer is not None else None
    out = compose_provider_results([(cfg(required=required), result)])
    decision, reason = req_expect if required else opt_expect
    assert out.decision == decision
    assert out.reasons == [reason]
    assert len(out.records) == 1
    rec = out.records[0]
    assert rec.required is required
    assert rec.status == ("unavailable" if result is None else ("ignored" if (answer == "UNKNOWN" and not required) else "ok"))


def test_unavailable_optional_is_recorded_and_skipped():
    out = compose_provider_results(
        [(cfg("opt", required=False), None)], meta={"opt": CallMeta(latency_ms=7, error="timeout")}
    )
    assert out.decision == Decision.ALLOW
    d = out.records[0].audit()
    assert d["status"] == "unavailable" and d["error"] == "timeout" and d["latency_ms"] == 7


def test_empty_provider_list_is_allow():
    out = compose_provider_results([])
    assert out.decision == Decision.ALLOW and out.reasons == [ReasonCode.OK] and out.records == []


_ANSWERS = ["ALLOW", "DENY", "UNKNOWN", "HUMAN_REVIEW", None]
_SEV = {"ALLOW": 0, "HUMAN_REVIEW": 2, "UNKNOWN": 4, "DENY": 6}


@pytest.mark.parametrize(("a", "b"), list(itertools.product(_ANSWERS, repeat=2)))
@pytest.mark.parametrize(("ra", "rb"), list(itertools.product([True, False], repeat=2)))
def test_two_providers_are_restrict_only_and_order_independent(a, b, ra, rb):
    def contribution(ans, required):
        if ans is None or ans == "UNKNOWN":
            return "UNKNOWN" if required else "ALLOW"
        return ans

    ca, cb = cfg("a", ra), cfg("b", rb)
    ra_, rb_ = (res(a, provider="a") if a else None), (res(b, provider="b") if b else None)
    fwd = compose_provider_results([(ca, ra_), (cb, rb_)])
    rev = compose_provider_results([(cb, rb_), (ca, ra_)])
    expected = max((contribution(a, ra), contribution(b, rb)), key=lambda d: _SEV[d])
    assert fwd.decision.value == expected == rev.decision.value
    assert set(fwd.reasons) == set(rev.reasons)
    # a lone ALLOW can never loosen: any non-ALLOW contribution wins
    if expected != "ALLOW":
        assert fwd.decision != Decision.ALLOW


def test_deny_plus_unavailable_reports_both_reasons_deny_wins():
    out = compose_provider_results([(cfg("a"), res("DENY")), (cfg("b"), None)])
    assert out.decision == Decision.DENY
    assert out.reasons == [ReasonCode.EXTERNAL_POLICY_DENIED, ReasonCode.EXTERNAL_POLICY_UNAVAILABLE]


def test_obligations_merged_tagged_and_valid_until_min():
    r1 = res("ALLOW", obligations=["mask:email", {"max_rows": 10}], valid_until="2026-01-01T00:10:00Z")
    r2 = res("ALLOW", obligations=["audit"], valid_until="2026-01-01T00:05:00Z", provider="b")
    out = compose_provider_results([(cfg("a"), r1), (cfg("b"), r2)], now=NOW)
    assert out.decision == Decision.ALLOW
    assert out.obligations == [
        {"provider": "a", "obligation": "mask:email"},
        {"provider": "a", "obligation": {"max_rows": 10}},
        {"provider": "b", "obligation": "audit"},
    ]
    assert out.valid_until == "2026-01-01T00:05:00.000000Z"
    assert out.revisions == ["a@r1", "b@r1"]
    detail = out.audit_detail()
    assert all(isinstance(o, str) for o in detail["obligations"])  # ledger-safe: no nested content-like keys


def test_stale_result_is_treated_as_unavailable():
    old = res("ALLOW", valid_until="2025-12-31T23:59:59Z")
    assert compose_provider_results([(cfg(required=True), old)], now=NOW).decision == Decision.UNKNOWN
    out = compose_provider_results([(cfg(required=False), old)], now=NOW)
    assert out.decision == Decision.ALLOW and out.records[0].status == "stale"


def test_audit_detail_shape():
    out = compose_provider_results([(cfg("opa1"), res("ALLOW", explanation_ref="trace/1"))],
                                   meta={"opa1": CallMeta(latency_ms=12)})
    rec = out.audit_detail()["providers"][0]
    assert rec == {
        "name": "opa1", "decision": "ALLOW", "policy_revision": "r1", "latency_ms": 12, "required": True,
        "status": "ok", "explanation_ref": "trace/1",
    }


def test_release_reasons():
    assert release_reasons(Decision.ALLOW, [ReasonCode.OK]) == [ReasonCode.OK]
    assert release_reasons(Decision.DENY, [ReasonCode.EXTERNAL_POLICY_DENIED]) == [
        ReasonCode.RELEASE_DENIED, ReasonCode.EXTERNAL_POLICY_DENIED]
    rr = ReleaseReceipt(receipt_id="x", decision=Decision.DENY, reason=[ReasonCode.RELEASE_DENIED],
                        valid_until="2026-01-01T00:00:00.000000Z", revocation_epoch=0, policy_version="p0")
    assert rr.model_dump(mode="json")["decision"] == "DENY"


# -------------------------------------------------------------------- application to verdicts / db
@pytest.fixture
def two(graph, session):
    a = make_env("source", classification="confidential")
    b = make_env("source", classification="public")
    graph.register_source(a)
    graph.register_source(b)
    session.commit()
    return a, b


def _out(session, *objs):
    r = req(*objs)
    return r, authorize_ex(session, r, NOW)


def test_build_provider_request_carries_verified_facts_only(session, two):
    a, b = two
    r, out = _out(session, a.context_id, b.context_id)
    pr = build_provider_request(r, out, action="send_email", destination="mail:acme.com")
    assert isinstance(pr, PolicyProviderRequest)
    assert pr.action == "send_email" and pr.destination == "mail:acme.com"
    assert {x.context_id: x.classification for x in pr.resource_refs} == {
        a.context_id: "confidential", b.context_id: "public"}
    assert pr.verified_context["ales_decision"] == "ALLOW"
    assert "content" not in str(pr.model_dump())


def test_needs_provider_call_skips_when_already_unrestorable(session, two):
    a, _ = two
    _, ok = _out(session, a.context_id)
    assert needs_provider_call(ok)
    _, unknown = _out(session, "no-such")
    assert not needs_provider_call(unknown)


def test_apply_deny_and_unavailable_restrict_only(session, two):
    a, _ = two
    r, out = _out(session, a.context_id)
    apply_composed(out, compose_provider_results([(cfg(), res("DENY"))]), session=session, request=r, now=NOW)
    assert out.response.decision == Decision.DENY
    assert out.response.reason == [ReasonCode.EXTERNAL_POLICY_DENIED]
    assert out.response.objects[0].decision == Decision.DENY

    r, out = _out(session, a.context_id)
    apply_composed(out, compose_provider_results([(cfg(), None)]), session=session, request=r, now=NOW)
    assert out.response.decision == Decision.UNKNOWN
    assert out.response.reason == [ReasonCode.EXTERNAL_POLICY_UNAVAILABLE]


def test_apply_never_loosens_an_existing_deny(session, two):
    a, _ = two
    r, out = _out(session, a.context_id)
    apply_composed(out, compose_provider_results([(cfg(), res("DENY"))]), session=session, request=r, now=NOW)
    before = out.response.model_copy(deep=True)
    apply_composed(out, compose_provider_results([(cfg(), res("ALLOW"))]), session=session, request=r, now=NOW)
    assert out.response.decision == before.decision == Decision.DENY
    apply_composed(out, compose_provider_results([(cfg(), None)]), session=session, request=r, now=NOW)
    assert out.response.decision == Decision.DENY  # UNKNOWN does not downgrade DENY


def test_apply_valid_until_is_min_with_provider(session, two):
    a, _ = two
    r, out = _out(session, a.context_id)
    composed = compose_provider_results([(cfg(), res("ALLOW", valid_until="2026-01-01T00:05:00Z"))], now=NOW)
    apply_composed(out, composed, session=session, request=r, now=NOW)
    assert out.response.decision == Decision.ALLOW
    assert out.response.valid_until == "2026-01-01T00:05:00.000000Z"
    assert out.response.objects[0].valid_until == "2026-01-01T00:05:00.000000Z"


def test_external_review_uses_approval_flow_and_binds_revision_and_destination(session, two):
    a, _ = two
    composed = compose_provider_results([(cfg(), res("HUMAN_REVIEW"))])
    r, out = _out(session, a.context_id)
    apply_composed(out, composed, session=session, request=r, now=NOW, destination="mail:x.com")
    assert out.response.decision == Decision.HUMAN_REVIEW
    assert ReasonCode.APPROVAL_PENDING in out.response.reason and ReasonCode.POLICY_HUMAN_REVIEW in out.response.reason
    assert out.approval_required and out.fingerprint and out.approval_context["external"] == ["p@r1"]
    row = ApprovalStore.ensure_pending(session, TENANT, out.fingerprint, out.approval_context, actor="svc",
                                       requested_by_principal="alice", now=NOW)
    ApprovalStore.decide(session, TENANT, row.approval_id, True, "boss", 3600, now=NOW)
    session.commit()

    # same fingerprint (principal, purpose, objects, provider revision, destination): honoured
    r2, out2 = _out(session, a.context_id)
    apply_composed(out2, composed, session=session, request=r2, now=NOW + timedelta(seconds=1),
                   destination="mail:x.com")
    assert out2.response.decision == Decision.ALLOW and out2.approval_id == row.approval_id
    assert out2.response.valid_until is not None  # capped at the approval's expiry

    # another destination does NOT inherit the approval
    r3, out3 = _out(session, a.context_id)
    apply_composed(out3, composed, session=session, request=r3, now=NOW + timedelta(seconds=1),
                   destination="mail:other.com")
    assert out3.response.decision == Decision.HUMAN_REVIEW

    # nor does a new provider revision
    composed2 = compose_provider_results([(cfg(), res("HUMAN_REVIEW", policy_revision="r2"))])
    r4, out4 = _out(session, a.context_id)
    apply_composed(out4, composed2, session=session, request=r4, now=NOW + timedelta(seconds=1),
                   destination="mail:x.com")
    assert out4.response.decision == Decision.HUMAN_REVIEW


def test_external_review_denied_approval_denies(session, two):
    a, _ = two
    composed = compose_provider_results([(cfg(), res("HUMAN_REVIEW"))])
    r, out = _out(session, a.context_id)
    apply_composed(out, composed, session=session, request=r, now=NOW)
    row = ApprovalStore.ensure_pending(session, TENANT, out.fingerprint, out.approval_context, actor="svc",
                                       requested_by_principal="alice", now=NOW)
    ApprovalStore.decide(session, TENANT, row.approval_id, False, "boss", 3600, now=NOW)
    session.commit()
    r2, out2 = _out(session, a.context_id)
    apply_composed(out2, composed, session=session, request=r2, now=NOW + timedelta(seconds=1))
    assert out2.response.decision == Decision.DENY
    assert ReasonCode.APPROVAL_DENIED in out2.response.reason


def test_migration_0005_roundtrip(tmp_path):
    from ales_core.migrations import current_revision, downgrade_migrations, run_migrations
    from sqlalchemy import create_engine, inspect

    eng = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    run_migrations(eng, "0004")
    assert "release_receipts" not in inspect(eng).get_table_names()
    run_migrations(eng, "0005")
    assert current_revision(eng) == "0005"
    cols = {c["name"] for c in inspect(eng).get_columns("release_receipts")}
    assert {"receipt_id", "tenant_id", "request_fingerprint", "decision", "detail", "created_at", "valid_until"} <= cols
    downgrade_migrations(eng, "0004")
    assert "release_receipts" not in inspect(eng).get_table_names()
