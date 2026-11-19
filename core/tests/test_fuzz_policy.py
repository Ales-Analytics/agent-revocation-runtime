"""Property-based tests for the policy engine, risk floors and tombstone matching."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ales_core.db import Tombstone
from ales_core.models import AffectedScope
from ales_core.policy import (
    _EFFECT_RANK,
    _RISK_RANK,
    WILDCARD,
    Effect,
    PolicyContext,
    PolicyDocument,
    Risk,
    effective_risk,
    evaluate_policy,
)
from ales_core.tombstones import applies, covers_node, normalize_scope
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

SETTINGS = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])

TXT = st.text(st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=8)
# Small alphabet so selectors and contexts collide often.
COLLIDE = st.sampled_from(["a", "b", "*", "é", "\U0001f600", "x y", "A", "ａ"])
VAL = COLLIDE | TXT
KINDS = ["source", "chunk", "embedding", "summary", "memory", "cache", "artifact"]
CLASSES = ["public", "internal", "confidential", "restricted"]


def selector(values=VAL):
    return st.none() | st.lists(values, min_size=1, max_size=3)


@st.composite
def rules(draw, idx):
    subj = draw(
        st.none()
        | st.builds(
            lambda p, t, a: {"principals": p, "principal_types": t, "agents": a},
            selector(),
            selector(st.sampled_from(["user", "agent", "service", "*"])),
            selector(),
        )
    )
    res = draw(
        st.none()
        | st.builds(
            lambda k, c, t: {"kinds": k, "classifications": c, "tools": t},
            selector(st.sampled_from(KINDS + ["*"])),
            selector(st.sampled_from(CLASSES + ["*"])),
            selector(),
        )
    )
    ob = draw(
        st.none()
        | st.builds(
            lambda m, f: {"max_classification": m, "require_fresh_lineage": f},
            st.none() | st.sampled_from(CLASSES),
            st.booleans(),
        )
    )
    return {
        "rule_id": f"r{idx}",
        "effect": draw(st.sampled_from([e.value for e in Effect])),
        "subjects": subj,
        "resources": res,
        "purposes": draw(selector()),
        "risk": draw(st.none() | st.sampled_from([r.value for r in Risk])),
        "obligations": ob,
    }


@st.composite
def docs(draw, max_rules=6):
    n = draw(st.integers(0, max_rules))
    return PolicyDocument.model_validate(
        {
            "policy_id": "p",
            "tenant_id": "t",
            "version": 1,
            "rules": [draw(rules(i)) for i in range(n)],
            "default_action": draw(st.sampled_from([e.value for e in Effect])),
            "risk_floors": draw(
                st.dictionaries(COLLIDE, st.sampled_from([r.value for r in Risk]), max_size=3)
            ),
            "created_by": "fuzz",
        }
    )


GARBAGE_RISK = (
    st.none() | st.sampled_from(["low", "medium", "high", "HIGH", "", " ", "critical", "none"]) | TXT
)


@st.composite
def contexts(draw):
    objs = draw(
        st.lists(
            st.builds(
                lambda k, c, m: {"kind": k, "classification": c, "tenant_mismatch": m},
                st.none() | st.sampled_from(KINDS + ["weird"]),
                st.none() | st.sampled_from(CLASSES + ["top-secret", "", "É"]),
                st.booleans(),
            ),
            max_size=4,
        )
    )
    return PolicyContext.model_validate(
        {
            "principal_id": draw(VAL | st.just("")),
            "principal_type": draw(st.sampled_from(["user", "agent", "service", "robot", ""])),
            "agent_id": draw(st.none() | VAL | st.just("")),
            "purpose": draw(VAL | st.just("")),
            "objects": objs,
            "tools": draw(st.lists(VAL, max_size=3)),
            "risk": draw(GARBAGE_RISK),
        }
    )


@SETTINGS
@given(docs(), contexts())
def test_evaluate_never_raises_and_is_deterministic(doc, ctx):
    out = evaluate_policy(doc, ctx)
    assert out == evaluate_policy(doc, ctx)
    assert out == evaluate_policy(doc, ctx.model_dump())  # dict form
    assert len(out.per_object) == max(1, len(ctx.objects))
    # Aggregate is the worst per-object effect, and carries a matching reason code.
    assert out.effect == max((p.effect for p in out.per_object), key=lambda e: _EFFECT_RANK[e])
    assert out.reasons
    if out.rule_id is not None:
        assert out.rule_id in {r.rule_id for r in doc.rules}


@SETTINGS
@given(docs(max_rules=0), contexts())
def test_empty_rules_follow_default_action_fail_closed(doc, ctx):
    out = evaluate_policy(doc, ctx)
    assert out.effect == doc.default_action
    assert out.rule_id is None and not out.require_fresh_lineage
    # Omitting default_action fails closed.
    omitted = PolicyDocument(policy_id="p", tenant_id="t", version=1, created_by="x")
    assert omitted.default_action == Effect.DENY
    assert evaluate_policy(omitted, ctx).effect == Effect.DENY


@SETTINGS
@given(docs(), contexts())
def test_leading_catch_all_deny_always_wins(doc, ctx):
    deny_all = {"rule_id": "zz-deny-all", "effect": "deny"}
    stricter = PolicyDocument.model_validate(
        {**doc.model_dump(mode="json"), "rules": [deny_all, *doc.model_dump(mode="json")["rules"]]}
    )
    out = evaluate_policy(stricter, ctx)
    assert out.effect == Effect.DENY and out.rule_id == "zz-deny-all"


@SETTINGS
@given(
    docs(),
    contexts(),
    st.lists(
        st.builds(lambda k: {"kind": k, "classification": "public"}, st.sampled_from(KINDS)), max_size=2
    ),
    st.lists(VAL, max_size=2),
)
def test_padding_objects_or_tools_never_lowers_effect(doc, ctx, extra_objs, extra_tools):
    """The "padding bypass" closure: extra benign objects/tools never lower the verdict.

    Holds when the original side is non-empty (an empty side is a single ``None`` pair that the
    padding replaces, which is a different question).
    """
    base = evaluate_policy(doc, ctx).effect
    padded = ctx.model_copy(
        update={
            "objects": [*ctx.objects, *(type(ctx.objects[0])(**o) for o in extra_objs)]
            if ctx.objects
            else ctx.objects,
            "tools": [*ctx.tools, *extra_tools] if ctx.tools else ctx.tools,
        }
    )
    assert _EFFECT_RANK[evaluate_policy(doc, padded).effect] >= _EFFECT_RANK[base]


@SETTINGS
@given(docs(), VAL | st.just(""), GARBAGE_RISK)
def test_effective_risk_floor_properties(doc, purpose, caller):
    eff = effective_risk(doc, purpose, caller)
    floors = [doc.risk_floors[k] for k in (purpose, WILDCARD) if k in doc.risk_floors]
    if not floors:
        assert eff == caller  # unchanged, garbage included
        return
    assert eff in {r.value for r in Risk}
    floor_rank = max(_RISK_RANK[f] for f in floors)
    assert _RISK_RANK[Risk(eff)] >= floor_rank
    if caller in {r.value for r in Risk}:
        assert _RISK_RANK[Risk(eff)] >= _RISK_RANK[Risk(caller)]
    assert _RISK_RANK[Risk(eff)] == max(
        floor_rank, _RISK_RANK[Risk(caller)] if caller in {r.value for r in Risk} else -1
    )


@SETTINGS
@given(docs(), contexts())
def test_floor_cannot_be_dodged_by_lowering_caller_risk(doc, ctx):
    """With a "*" floor of high, a rule keyed on risk=high matches whatever risk the caller claims."""
    high_floor = doc.model_copy(update={"risk_floors": {**doc.risk_floors, WILDCARD: Risk.HIGH}})
    outs = {
        evaluate_policy(high_floor, ctx.model_copy(update={"risk": r})).model_dump_json()
        for r in (None, "low", "medium", "high", "garbage")
    }
    assert len(outs) == 1


DT = st.datetimes(min_value=datetime(2000, 1, 1), max_value=datetime(2100, 1, 1)) | st.datetimes(
    min_value=datetime(2000, 1, 1), max_value=datetime(2100, 1, 1), timezones=st.just(UTC)
)
SCOPE_LIST = st.none() | st.lists(VAL | st.just(""), max_size=3)


def _utc(d: datetime) -> datetime:
    return d.replace(tzinfo=UTC) if d.tzinfo is None else d.astimezone(UTC)


@SETTINGS
@given(
    SCOPE_LIST,
    SCOPE_LIST,
    VAL | st.just(""),
    VAL | st.just(""),
    DT,
    DT,
)
def test_tombstone_applies_semantics(sp, sq, principal, purpose, effective, now):
    t = Tombstone(
        tenant_id="t",
        event_id="e",
        context_id="c",
        object_version=None,
        reason="deleted",
        effective_at=effective,
        scope_principals=sp,
        scope_purposes=sq,
    )
    got = applies(t, principal, purpose, now)
    assert isinstance(got, bool)
    if _utc(now) < _utc(effective):
        assert got is False  # delayed revocation never applies early
        return
    expect = (not sp or principal in sp) and (not sq or purpose in sq)
    assert got is expect
    if not sp and not sq:
        assert got is True and not t.scoped  # empty/absent on both axes = unscoped, matches everyone
    # Exact comparison: no case-folding or unicode normalisation.
    if sp and principal not in sp:
        assert got is False


@SETTINGS
@given(
    st.none() | st.builds(AffectedScope, principals=SCOPE_LIST, purposes=SCOPE_LIST),
    VAL | st.just(""),
    VAL | st.just(""),
)
def test_normalize_scope_roundtrip_matches_original(scope, principal, purpose):
    p, q = normalize_scope(scope)
    assert p is None or (p == sorted(set(p)) and p)
    assert q is None or (q == sorted(set(q)) and q)
    t = Tombstone(
        tenant_id="t",
        event_id="e",
        context_id="c",
        object_version=None,
        reason="deleted",
        effective_at=datetime(2000, 1, 1, tzinfo=UTC),
        scope_principals=p,
        scope_purposes=q,
    )
    now = datetime(2001, 1, 1, tzinfo=UTC)
    orig_p = (scope.principals if scope else None) or []
    orig_q = (scope.purposes if scope else None) or []
    expect = (not orig_p or principal in orig_p) and (not orig_q or purpose in orig_q)
    assert applies(t, principal, purpose, now + timedelta(days=1)) is expect


@SETTINGS
@given(VAL, VAL, st.none() | VAL, VAL, VAL)
def test_covers_node(cid, version, tver, qcid, qver):
    t = Tombstone(
        tenant_id="t",
        event_id="e",
        context_id=cid,
        object_version=tver,
        reason="deleted",
        effective_at=datetime(2000, 1, 1, tzinfo=UTC),
    )
    got = covers_node(t, qcid, qver)
    assert got is (cid == qcid and (tver is None or tver == qver))
    assert covers_node(t, cid, version) is (tver is None or tver == version)
