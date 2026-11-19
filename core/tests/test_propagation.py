from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from ales_core import AuthorityWidening, Classification, TrustState, check_not_wider, effective_authority
from hypothesis import given
from hypothesis import strategies as st

BASE = datetime(2026, 1, 1, tzinfo=UTC)

scopes = st.none() | st.lists(
    st.sampled_from(list("abcdef")), max_size=4, unique=True
)  # None = unrestricted, [] = nobody
expiries = st.one_of(st.none(), st.integers(0, 1000).map(lambda d: BASE + timedelta(days=d)))
parent = st.builds(
    SimpleNamespace,
    classification=st.sampled_from([c.value for c in Classification]),
    trust_state=st.sampled_from([t.value for t in TrustState]),
    principal_scope=scopes,
    purpose_scope=scopes,
    expires_at=expiries,
)
parents = st.lists(parent, min_size=1, max_size=5)


def allows(scope: frozenset | None, item: str) -> bool:
    return scope is None or item in scope


@given(parents)
def test_never_more_permissive_than_any_parent(ps):
    eff = effective_authority(ps)
    for p in ps:
        assert eff.classification.rank >= Classification(p.classification).rank
        assert eff.trust_state.rank >= TrustState(p.trust_state).rank
        for item in "abcdefz":
            if allows(eff.principal_scope, item):
                assert p.principal_scope is None or item in p.principal_scope
            if allows(eff.purpose_scope, item):
                assert p.purpose_scope is None or item in p.purpose_scope
        if p.expires_at is not None:
            assert eff.expires_at is not None and eff.expires_at <= p.expires_at


@given(parents)
def test_order_independent(ps):
    assert effective_authority(ps) == effective_authority(list(reversed(ps)))


@given(parents)
def test_computed_authority_itself_passes_check(ps):
    eff = effective_authority(ps)
    claimed = SimpleNamespace(
        classification=eff.classification.value,
        trust_state=eff.trust_state.value,
        principal_scope=None if eff.principal_scope is None else sorted(eff.principal_scope),
        purpose_scope=None if eff.purpose_scope is None else sorted(eff.purpose_scope),
        expires_at=eff.expires_at,
    )
    check_not_wider(claimed, eff)


def P(**kw):
    d = {
        "classification": "internal",
        "trust_state": "verified",
        "principal_scope": None,
        "purpose_scope": None,
        "expires_at": None,
    }
    d.update(kw)
    return SimpleNamespace(**d)


def test_most_restrictive_classification():
    eff = effective_authority(
        [P(classification="public"), P(classification="restricted"), P(classification="internal")]
    )
    assert eff.classification == Classification.RESTRICTED


def test_least_trusted():
    eff = effective_authority([P(trust_state="verified"), P(trust_state="untrusted")])
    assert eff.trust_state == TrustState.UNTRUSTED
    eff = effective_authority([P(trust_state="quarantined"), P(trust_state="untrusted")])
    assert eff.trust_state == TrustState.QUARANTINED


def test_scope_intersection_and_unrestricted():
    eff = effective_authority([P(principal_scope=["a", "b"]), P(principal_scope=["b", "c"]), P()])
    assert eff.principal_scope == frozenset({"b"})
    assert effective_authority([P(), P()]).principal_scope is None


def test_disjoint_scopes_mean_nobody_not_unrestricted():
    eff = effective_authority([P(principal_scope=["a"]), P(principal_scope=["b"])])
    assert eff.principal_scope == frozenset()


def test_earliest_expiry():
    e1, e2 = BASE + timedelta(days=1), BASE + timedelta(days=5)
    assert effective_authority([P(expires_at=e2), P(), P(expires_at=e1)]).expires_at == e1
    assert effective_authority([P(), P()]).expires_at is None


def test_empty_parents_rejected():
    with pytest.raises(ValueError):
        effective_authority([])


E2 = BASE + timedelta(days=2)


def Q(**kw):
    d = {"classification": "restricted", "principal_scope": ["a"], "purpose_scope": ["x"], "expires_at": E2}
    d.update(kw)
    return P(**d)


@pytest.mark.parametrize(
    "claimed",
    [
        Q(classification="confidential"),
        Q(principal_scope=None),
        Q(principal_scope=["a", "b"]),
        Q(purpose_scope=None),
        Q(purpose_scope=["z"]),
        Q(expires_at=BASE + timedelta(days=9)),
        Q(expires_at=None),
    ],
)
def test_check_not_wider_rejects(claimed):
    computed = effective_authority([Q()])
    with pytest.raises(AuthorityWidening):
        check_not_wider(claimed, computed)


def test_check_not_wider_rejects_trust_upgrade():
    computed = effective_authority([Q(trust_state="untrusted")])
    with pytest.raises(AuthorityWidening):
        check_not_wider(Q(trust_state="verified"), computed)


def test_check_not_wider_accepts_narrower():
    computed = effective_authority([P(classification="internal", principal_scope=["a", "b"])])
    check_not_wider(
        P(classification="restricted", principal_scope=["a"], trust_state="quarantined"), computed
    )


def test_empty_scope_is_nobody_and_never_unrestricted():
    eff = effective_authority([P(principal_scope=[]), P()])
    assert eff.principal_scope == frozenset()
    # an empty claim is the narrowest possible and is accepted under any computed scope
    check_not_wider(Q(principal_scope=[], purpose_scope=[]), effective_authority([Q()]))
    check_not_wider(Q(principal_scope=[]), effective_authority([P(principal_scope=[])]))
    # but an unrestricted claim under an empty computed scope is a genuine widening
    with pytest.raises(AuthorityWidening):
        check_not_wider(P(), effective_authority([P(principal_scope=[])]))
