"""ALES INVARIANT Python SDK."""

from .client import (
    MAX_REQUEST_BYTES,
    AuthorizeResult,
    InvariantClient,
    ObjectVerdict,
)
from .decision_cache import DecisionCache, make_key
from .envelope import digest, new_derivative, new_source, now_iso
from .errors import (
    AlesConnectionError,
    AlesError,
    AlesHTTPError,
    AlesTimeoutError,
    AuthError,
    ConfigError,
    InvalidRequestError,
    RequestTooLargeError,
    ResponseError,
    ServerUnavailableError,
    SessionResetRequired,
    SnapshotError,
    TenantMismatchError,
)
from .fail_modes import EffectiveAction, FailMode, resolve
from .session_taint import SessionTaint, TaintVerdict, enforce
from .snapshot import Snapshot, canonical_bytes
from .wrappers import Blocked, guard_cache_get, guard_memory_read, guard_retrieval

__version__ = "0.2.0"

__all__ = [
    "MAX_REQUEST_BYTES",
    "AlesConnectionError",
    "AlesError",
    "AlesHTTPError",
    "AlesTimeoutError",
    "AuthError",
    "AuthorizeResult",
    "Blocked",
    "ConfigError",
    "DecisionCache",
    "EffectiveAction",
    "FailMode",
    "InvalidRequestError",
    "InvariantClient",
    "ObjectVerdict",
    "RequestTooLargeError",
    "ResponseError",
    "ServerUnavailableError",
    "SessionResetRequired",
    "SessionTaint",
    "Snapshot",
    "SnapshotError",
    "TaintVerdict",
    "TenantMismatchError",
    "canonical_bytes",
    "digest",
    "enforce",
    "guard_cache_get",
    "guard_memory_read",
    "guard_retrieval",
    "make_key",
    "new_derivative",
    "new_source",
    "now_iso",
    "resolve",
]
