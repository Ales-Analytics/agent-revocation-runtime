"""Pure authority propagation: a derivative is never more permissive than any parent.

Scope representation in EffectiveAuthority: ``None`` means unrestricted (envelope scope
``[]``); a frozenset is a closed allow-list, and an *empty* frozenset means nobody.
This distinction keeps disjoint intersections from silently becoming unrestricted.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .exceptions import AuthorityWidening
from .models import Classification, TrustState


@dataclass(frozen=True)
class EffectiveAuthority:
    classification: Classification
    principal_scope: frozenset[str] | None
    purpose_scope: frozenset[str] | None
    expires_at: datetime | None
    trust_state: TrustState


def _intersect(a: frozenset[str] | None, b: frozenset[str] | None) -> frozenset[str] | None:
    if a is None:
        return b
    if b is None:
        return a
    return a & b


def _scope(value: Iterable[str] | None) -> frozenset[str] | None:
    items = list(value or [])
    return frozenset(items) if items else None


def effective_authority(parents: Iterable[Any]) -> EffectiveAuthority:
    """Combine parents (envelopes or ORM rows; duck-typed) into the most restrictive authority."""
    ps = list(parents)
    if not ps:
        raise ValueError("effective_authority requires at least one parent")
    classification = max((Classification(p.classification) for p in ps), key=lambda c: c.rank)
    trust = max((TrustState(p.trust_state) for p in ps), key=lambda t: t.rank)
    principals: frozenset[str] | None = None
    purposes: frozenset[str] | None = None
    expiries: list[datetime] = []
    for p in ps:
        principals = _intersect(principals, _scope(p.principal_scope))
        purposes = _intersect(purposes, _scope(p.purpose_scope))
        if p.expires_at is not None:
            expiries.append(p.expires_at)
    return EffectiveAuthority(
        classification=classification,
        principal_scope=principals,
        purpose_scope=purposes,
        expires_at=min(expiries) if expiries else None,
        trust_state=trust,
    )


def _scope_wider(claimed: frozenset[str] | None, allowed: frozenset[str] | None) -> bool:
    if allowed is None:
        return False
    if claimed is None:
        return True
    return not claimed <= allowed


def check_not_wider(claimed: Any, computed: EffectiveAuthority) -> None:
    """Raise AuthorityWidening if `claimed` (envelope/row) exceeds `computed` on any axis."""
    problems: list[str] = []
    if Classification(claimed.classification).rank < computed.classification.rank:
        problems.append("classification")
    if TrustState(claimed.trust_state).rank < computed.trust_state.rank:
        problems.append("trust_state")
    if _scope_wider(_scope(claimed.principal_scope), computed.principal_scope):
        problems.append("principal_scope")
    if _scope_wider(_scope(claimed.purpose_scope), computed.purpose_scope):
        problems.append("purpose_scope")
    if computed.expires_at is not None and (
        claimed.expires_at is None or claimed.expires_at > computed.expires_at
    ):
        problems.append("expires_at")
    if problems:
        raise AuthorityWidening(f"derivative claims wider authority than parents on: {', '.join(problems)}")
