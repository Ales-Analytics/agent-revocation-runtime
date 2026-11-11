"""Fail modes: how a decision is turned into an effective allow/block action."""

from __future__ import annotations

import enum
from dataclasses import dataclass


class FailMode(str, enum.Enum):
    OBSERVE = "OBSERVE"
    WARN = "WARN"
    ENFORCE = "ENFORCE"
    BOUNDED_OFFLINE = "BOUNDED_OFFLINE"


@dataclass(frozen=True)
class EffectiveAction:
    allow: bool
    needs_override: bool = False
    observed_only: bool = False


def is_protected(classification: str | None) -> bool:
    """Everything except an explicit ``public`` classification is protected (unknown => protected)."""
    return (classification or "restricted") != "public"


def resolve(
    decision: str,
    mode: FailMode | str,
    classification: str | None = None,
    lease_ok: bool | None = None,
) -> EffectiveAction:
    """Resolve a server/cached decision into an action.

    ``lease_ok`` only matters for BOUNDED_OFFLINE: ``None`` means the server was reachable (behaves
    like ENFORCE), ``True`` means offline with a valid lease (decision comes from the decision cache,
    ALLOW only), ``False`` means offline with an expired lease (protected reads are denied).
    Only an explicit ALLOW is ever allowed unconditionally; REFRESH/REDACT/HUMAN_REVIEW are not
    raw-usable and therefore block under ENFORCE.
    """
    mode = FailMode(mode)
    decision = str(getattr(decision, "value", decision))
    allowed = decision == "ALLOW"
    protected = is_protected(classification)

    if mode is FailMode.OBSERVE:
        return EffectiveAction(allow=True, observed_only=not allowed)
    if mode is FailMode.WARN:
        if allowed:
            return EffectiveAction(allow=True)
        if protected:
            return EffectiveAction(allow=False, needs_override=True)
        return EffectiveAction(allow=True, observed_only=True)
    if mode is FailMode.BOUNDED_OFFLINE and lease_ok is False:
        # Lease expired: no authority to serve anything protected, even a cached ALLOW.
        return EffectiveAction(allow=(not protected) and decision not in ("DENY", "QUARANTINE"))
    return EffectiveAction(allow=allowed)
