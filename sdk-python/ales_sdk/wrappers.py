"""Generic enforcement helpers built on a single ``_guard`` core."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

from .client import AuthorizeResult, InvariantClient
from .errors import ConfigError, SessionResetRequired
from .fail_modes import resolve
from .session_taint import enforce

T = TypeVar("T")


@dataclass
class Blocked:
    item: Any
    context_id: str
    decision: str
    reasons: list[str] = field(default_factory=list)
    needs_override: bool = False


def _guard(
    client: InvariantClient,
    principal: Mapping[str, str],
    purpose: str,
    items: Sequence[T],
    id_getter: Callable[[T], str],
    *,
    version_getter: Callable[[T], str | None] | None = None,
    classification_getter: Callable[[T], str | None] | None = None,
    agent_id: str | None = None,
    session_id: str | None = None,
    taint_check: str = "off",
) -> tuple[list[T], list[Blocked], AuthorizeResult | None]:
    """Core enforcement.

    taint_check="pre" (requires session_id) first re-authorizes everything the session has
    already consumed and raises SessionResetRequired if any of it is no longer allowed, so a
    revoked exposure is never silently carried forward. "off" (default) skips that check.
    """
    if taint_check not in ("pre", "off"):
        raise ConfigError(f"taint_check must be 'pre' or 'off', got {taint_check!r}")
    if taint_check == "pre":
        if not session_id:
            raise ConfigError("taint_check='pre' requires a session_id")
        taint = enforce(session_id, client)
        if taint.reset_required:
            raise SessionResetRequired(taint)
    if not items:
        return [], [], None
    ids = [id_getter(i) for i in items]
    versions = [version_getter(i) if version_getter else None for i in items]
    objects = list(zip(ids, versions, strict=True))
    result = client.authorize(principal, purpose, objects, agent_id=agent_id, session_id=session_id)

    allowed: list[T] = []
    blocked: list[Blocked] = []
    for item, context_id, version in zip(items, ids, versions, strict=True):
        verdict = result.verdict_for(context_id, version)
        decision = verdict.decision if verdict else "UNKNOWN"
        reasons = list(verdict.reason) if verdict else ["OBJECT_UNKNOWN"]
        cls = classification_getter(item) if classification_getter else None
        action = resolve(decision, client.fail_mode, cls, result.lease_ok)
        if action.allow:
            allowed.append(item)
        else:
            blocked.append(Blocked(item, context_id, decision, reasons, action.needs_override))

    if session_id:
        allowed_pairs = [(id_getter(i), version_getter(i) if version_getter else None) for i in allowed]
        client.session_taint.record(
            session_id,
            allowed_pairs,
            principal=principal,
            purpose=purpose,
        )
    return allowed, blocked, result


def guard_retrieval(
    client: InvariantClient,
    principal: Mapping[str, str],
    purpose: str,
    results: Sequence[T],
    id_getter: Callable[[T], str],
    **kw: Any,
) -> tuple[list[T], list[Blocked]]:
    """Filter retrieval hits (RAG chunks etc.) down to those the principal may use now."""
    allowed, blocked, _ = _guard(client, principal, purpose, results, id_getter, **kw)
    return allowed, blocked


def guard_memory_read(
    client: InvariantClient,
    principal: Mapping[str, str],
    purpose: str,
    memories: Sequence[T],
    id_getter: Callable[[T], str],
    **kw: Any,
) -> tuple[list[T], list[Blocked]]:
    """Filter agent-memory records before they are injected into a prompt."""
    allowed, blocked, _ = _guard(client, principal, purpose, memories, id_getter, **kw)
    return allowed, blocked


def guard_cache_get(
    client: InvariantClient,
    principal: Mapping[str, str],
    purpose: str,
    cached_value: T | None,
    context_ids: Sequence[str],
    **kw: Any,
) -> tuple[T | None, list[Blocked]]:
    """Gate a response/semantic-cache hit: usable only if every context it was built from is allowed.

    Returns ``(value, [])`` on success or ``(None, blocked)`` if any parent is blocked.
    """
    if cached_value is None:
        return None, []
    allowed, blocked, _ = _guard(client, principal, purpose, list(context_ids), lambda c: c, **kw)
    if blocked or len(allowed) != len(context_ids):
        return None, blocked
    return cached_value, []
