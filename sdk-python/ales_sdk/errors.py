"""Structured exception hierarchy for the ALES INVARIANT SDK.

Every error raised by the SDK derives from :class:`AlesError`. Enforcement code should treat *any*
``AlesError`` as "do not serve the protected object" (fail closed); the subclasses exist so that
operators can distinguish misconfiguration (``ConfigError``, ``AuthError``) from outages
(``AlesConnectionError``, ``ServerUnavailableError``) and tampering (``SnapshotError``).

::

    AlesError
    |-- ConfigError                      bad constructor arguments / missing optional dependency
    |-- InvalidRequestError              request cannot be serialised or violates a client-side guard
    |   `-- RequestTooLargeError         serialised payload exceeds MAX_REQUEST_BYTES
    |-- AlesConnectionError              transport failure (DNS, refused, reset ...)
    |   `-- AlesTimeoutError             connect/read/write/pool timeout
    |-- AlesHTTPError                    non-2xx response
    |   |-- AuthError                    401 / 403
    |   |   `-- TenantMismatchError      403 because the token's tenant differs from ours (fatal config error)
    |   `-- ServerUnavailableError       429 / 502 / 503 / 504 (retryable; treated as offline by authorize)
    |-- ResponseError                    2xx response that is not valid JSON / not the expected shape
    |-- SnapshotError                    signed policy snapshot failed verification
    |-- SessionResetRequired             a session consumed context that is no longer allowed
    |-- HumanReviewPending               policy requires operator approval before context is used
    |-- HandoffDenied                    agent-to-agent handoff not authorized
    |-- UntrackedContextError            model gateway (untracked="error") met items with no ALES id
    `-- CircuitOpen                      transport circuit breaker is open (internal fast-fail)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from .session_taint import TaintVerdict


class AlesError(Exception):
    """Base SDK error."""


class ConfigError(AlesError, ValueError):
    """The client was constructed with invalid or insufficient configuration."""


class InvalidRequestError(AlesError, ValueError):
    """The request was refused client-side before being sent."""


class RequestTooLargeError(InvalidRequestError):
    """The serialised request body exceeds the client-side size guard."""

    def __init__(self, size: int, limit: int) -> None:
        super().__init__(f"request body is {size} bytes; client-side limit is {limit} bytes")
        self.size = size
        self.limit = limit


class AlesConnectionError(AlesError):
    """Server unreachable."""


class AlesTimeoutError(AlesConnectionError):
    """The server did not answer within the configured timeout."""


class AlesHTTPError(AlesError):
    def __init__(self, status_code: int, body: Any, url: str = "") -> None:
        super().__init__(f"HTTP {status_code} from {url}: {body!r}")
        self.status_code = status_code
        self.body = body
        self.url = url

    @property
    def detail(self) -> str:
        """Best-effort human-readable server detail."""
        b = self.body
        if isinstance(b, dict):
            for k in ("detail", "error", "message"):
                if k in b and b[k] is not None:
                    return str(b[k])
        return str(b)


class AuthError(AlesHTTPError):
    """401/403: the bearer token is missing, invalid, expired or lacks the required role."""

    def __init__(self, status_code: int, body: Any, url: str = "") -> None:
        super().__init__(status_code, body, url)
        self.args = (f"authentication/authorization failed (HTTP {status_code}) at {url}: {self.detail}",)


class TenantMismatchError(AuthError):
    """403: the tenant the client claims is not the tenant bound to its token.

    This is a fatal configuration error: fix ``tenant_id`` or the token. It is never retried.
    """

    def __init__(self, status_code: int, body: Any, url: str = "", tenant_id: str = "") -> None:
        super().__init__(status_code, body, url)
        self.tenant_id = tenant_id
        msg = (
            f"tenant mismatch: client is configured for tenant {tenant_id!r} but the server rejected it "
            f"(HTTP {status_code}: {self.detail}). The tenant is derived from the auth token; "
            "check that tenant_id matches the token's tenant."
        )
        self.args = (msg,)


class ServerUnavailableError(AlesHTTPError):
    """429/502/503/504: the service is temporarily unavailable or shedding load."""


class ResponseError(AlesError):
    """The server answered 2xx but the body was malformed."""


class SnapshotError(AlesError):
    """A signed policy snapshot failed verification. ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, message: str = "") -> None:
        super().__init__(f"policy snapshot rejected ({reason}){': ' + message if message else ''}")
        self.reason = reason


class SessionResetRequired(AlesError):
    """The session consumed context that is no longer allowed; discard its state before continuing."""

    def __init__(self, verdict: TaintVerdict) -> None:
        ids = [v.context_id for v in verdict.revoked] + list(verdict.unverifiable)
        super().__init__(f"session {verdict.session_id!r} must be reset; affected contexts: {ids}")
        self.verdict = verdict


class HumanReviewPending(AlesError):
    """Policy returned HUMAN_REVIEW: an operator must approve before the context may be used."""

    def __init__(self, context_ids: list[str], reasons: list[str]) -> None:
        self.context_ids = list(context_ids)
        self.reasons = list(reasons)
        self.approval_hint = (
            "approval required (" + ", ".join(self.reasons) + ")" if self.reasons else "approval required"
        )
        super().__init__(f"human review pending for {self.context_ids}: {self.approval_hint}")


class HandoffDenied(AlesError):
    """The agent-to-agent handoff was not authorized."""

    def __init__(self, reasons: list[str]) -> None:
        self.reasons = list(reasons)
        super().__init__(f"handoff denied: {self.reasons}")


class UntrackedContextError(AlesError):
    """The model gateway was configured with ``untracked="error"`` and met items carrying no ALES id."""

    def __init__(self, indices: list[int]) -> None:
        self.indices = list(indices)
        super().__init__(f"untracked context (no ALES id) at item indices {self.indices}")


class CircuitOpen(AlesConnectionError):
    """The transport circuit breaker is open; the request was not sent."""
