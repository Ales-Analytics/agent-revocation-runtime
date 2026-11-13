"""Agent-to-agent handoff: authorize the delegation and carry session taint across.

Server contract (``POST /v1/handoffs``): request ``{from_workload, to_workload, purpose}`` (tenant from
the ``X-Tenant-Id`` header / token); response ``{decision: ALLOW|DENY|UNKNOWN|HUMAN_REVIEW,
reason: [str]}``. Missing delegation => DENY ``DELEGATION_MISSING``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .client import InvariantClient
from .errors import (
    AlesConnectionError,
    AlesError,
    AlesHTTPError,
    ConfigError,
    HandoffDenied,
    HumanReviewPending,
)
from .fail_modes import FailMode, resolve

__all__ = ["HandoffResult", "handoff"]


@dataclass
class HandoffResult:
    from_session: str
    to_session: str
    context_ids: set[str] = field(default_factory=set)
    exposures_copied: int = 0
    decision: str | None = None  # None when no workloads were given (local transfer only)
    reasons: list[str] = field(default_factory=list)


def handoff(
    client: InvariantClient,
    from_session: str,
    to_session: str,
    *,
    from_workload: str | None = None,
    to_workload: str | None = None,
    purpose: str,
) -> HandoffResult:
    """Hand ``from_session``'s context over to ``to_session``.

    With workloads, the server must authorize the delegation first; DENY raises
    :class:`HandoffDenied` and nothing is transferred. An undeployed endpoint (404) or an unreachable
    server is UNKNOWN and goes through the fail mode (ENFORCE/BOUNDED_OFFLINE/WARN deny, OBSERVE
    proceeds). Without workloads only the local taint transfer happens.
    """
    if (from_workload is None) != (to_workload is None):
        raise ConfigError("pass both from_workload and to_workload, or neither")
    decision: str | None = None
    reasons: list[str] = []
    if from_workload is not None and to_workload is not None:
        decision, reasons = _authorize(client, from_workload, to_workload, purpose)
        if decision == "HUMAN_REVIEW" and client.fail_mode in (FailMode.ENFORCE, FailMode.BOUNDED_OFFLINE):
            raise HumanReviewPending([], reasons)
        if not resolve(decision, client.fail_mode, None, None).allow:
            raise HandoffDenied(reasons or [decision])
    copied = client.session_taint.transfer(from_session, to_session)
    return HandoffResult(
        from_session, to_session, client.session_taint.contexts_for(to_session), copied, decision, reasons
    )


def _authorize(client: InvariantClient, src: str, dst: str, purpose: str) -> tuple[str, list[str]]:
    try:
        data = client.authorize_handoff(src, dst, purpose)
    except AlesHTTPError as e:
        if e.status_code == 404:
            return "UNKNOWN", ["HANDOFF_ENDPOINT_UNAVAILABLE"]
        if e.status_code in (429, 502, 503, 504):
            return "UNKNOWN", ["HANDOFF_SERVER_UNAVAILABLE"]
        raise
    except AlesConnectionError:
        return "UNKNOWN", ["HANDOFF_SERVER_UNAVAILABLE"]
    try:
        return str(data["decision"]), [str(r) for r in data.get("reason", [])]
    except (KeyError, TypeError, AttributeError) as e:
        raise AlesError(f"malformed handoff response: {e!r}") from e
