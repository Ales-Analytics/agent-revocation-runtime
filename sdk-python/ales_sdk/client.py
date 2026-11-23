"""Synchronous HTTP client for the Agent Revocation Runtime decision API."""

from __future__ import annotations

import json as _json
import logging
import random
import threading
import time
import urllib.parse
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Self

import httpx

from .decision_cache import DecisionCache, make_key
from .envelope import now_iso
from .errors import (
    AlesConnectionError,
    AlesError,
    AlesHTTPError,
    AlesTimeoutError,
    AuthError,
    ConfigError,
    HumanReviewPending,
    InvalidRequestError,
    ReleaseDenied,
    RequestTooLargeError,
    ResponseError,
    ServerUnavailableError,
    SnapshotError,
    TenantMismatchError,
)
from .fail_modes import FailMode, resolve
from .resilience import BreakerState, CircuitBreaker
from .session_taint import SessionTaint
from .snapshot import Snapshot, load_public_keys, verify_snapshot

__all__ = [
    "MAX_REQUEST_BYTES",
    "AlesConnectionError",
    "AlesError",
    "AlesHTTPError",
    "AuthorizeResult",
    "InvariantClient",
    "ObjectVerdict",
    "ReleaseReceipt",
]

log = logging.getLogger("ales_sdk")

MAX_REQUEST_BYTES = 1_000_000  # client-side request size guard (1 MB)
DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=3.0)  # connect 3s / read 10s
RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
SNAPSHOT_RETRY_INTERVAL = 1.0  # min seconds between failed opportunistic snapshot fetches


@dataclass
class ObjectVerdict:
    context_id: str
    decision: str
    reason: list[str] = field(default_factory=list)
    version: str | None = None
    valid_until: str | None = None


@dataclass
class AuthorizeResult:
    decision: str
    reason: list[str]
    revocation_epoch: int
    policy_version: str
    trace_id: str
    objects: list[ObjectVerdict] = field(default_factory=list)
    valid_until: str | None = None
    from_cache: bool = False
    offline: bool = False
    lease_ok: bool | None = None  # None = server reachable; True/False = offline lease state

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    def verdict_for(self, context_id: str, version: str | None = None) -> ObjectVerdict | None:
        """The verdict for ``context_id`` at exactly ``version``.

        With ``version`` given, only a verdict carrying that version matches (a verdict without a
        version, from a server that does not echo it, matches only when nothing contradicts ours). A
        verdict for a *different* version never answers for this one. With ``version`` omitted the server
        resolved "latest"; if several verdicts share the id the most restrictive wins.
        """
        return match_verdict(self.objects, context_id, version)

    @classmethod
    def from_response(cls, data: Mapping[str, Any]) -> AuthorizeResult:
        try:
            return cls(
                decision=str(data["decision"]),
                reason=list(data.get("reason", [])),
                revocation_epoch=int(data["revocation_epoch"]),
                policy_version=str(data["policy_version"]),
                trace_id=str(data["trace_id"]),
                objects=[
                    ObjectVerdict(
                        o["context_id"],
                        str(o["decision"]),
                        list(o.get("reason", [])),
                        o.get("version"),
                        o.get("valid_until"),
                    )
                    for o in data.get("objects", [])
                ],
                valid_until=data.get("valid_until"),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise ResponseError(f"malformed authorize response: {e!r}") from e


@dataclass
class ReleaseReceipt:
    """``POST /v1/releases`` answer. Short-lived and request-bound; never cached by the SDK.

    ``synthesised`` is True when the gate could not be reached and the SDK itself produced the UNKNOWN
    receipt (``receipt_id`` is then empty)."""

    receipt_id: str
    decision: str
    reason: list[str]
    valid_until: str
    revocation_epoch: int
    policy_version: str
    synthesised: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    @classmethod
    def from_response(cls, data: Mapping[str, Any]) -> ReleaseReceipt:
        try:
            return cls(
                receipt_id=str(data["receipt_id"]),
                decision=str(data["decision"]),
                reason=[str(r) for r in data.get("reason", [])],
                valid_until=str(data["valid_until"]),
                revocation_epoch=int(data["revocation_epoch"]),
                policy_version=str(data["policy_version"]),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise ResponseError(f"malformed release receipt: {e!r}") from e


def _most_restrictive(cands: list[ObjectVerdict]) -> ObjectVerdict | None:
    return next((verdict for verdict in cands if verdict.decision != "ALLOW"), cands[0] if cands else None)


def match_verdict(
    objects: Iterable[ObjectVerdict], context_id: str, version: str | None
) -> ObjectVerdict | None:
    """Pick the verdict for exactly ``(context_id, version)``; ``None`` if none answers for it."""
    candidates = [verdict for verdict in objects if verdict.context_id == context_id]
    if version is None:
        return _most_restrictive(candidates)
    exact = [verdict for verdict in candidates if verdict.version == version]
    if exact:
        return _most_restrictive(exact)
    unversioned = [verdict for verdict in candidates if verdict.version is None]
    if len(unversioned) == len(candidates):
        return _most_restrictive(unversioned)  # server did not echo versions: nothing contradicts ours
    return None


def _spec_for_verdict(objs: list[dict[str, Any]], o: ObjectVerdict) -> dict[str, Any] | None:
    """The requested object a verdict answers for, matched on (context_id, version).

    A verdict carrying a version matches the request for exactly that version, or the sole request that
    omitted a version (server resolved "latest"). A verdict without a version matches only when the id was
    requested once. Anything else is unattributable and is not cached.
    """
    matching_requests = [reference for reference in objs if reference["context_id"] == o.context_id]
    if o.version is not None:
        exact = [reference for reference in matching_requests if reference.get("version") == o.version]
        if exact:
            return exact[0]
        return (
            matching_requests[0]
            if len(matching_requests) == 1 and matching_requests[0].get("version") is None
            else None
        )
    return matching_requests[0] if len(matching_requests) == 1 else None


def _parse_rfc3339(value: str) -> float:
    timestamp = datetime.fromisoformat(value)
    if timestamp.tzinfo is None:
        raise ValueError("valid_until has no timezone")
    return timestamp.timestamp()


def _object_reference(value: Any) -> dict[str, Any]:
    match value:
        case str():
            return {"context_id": value}
        case tuple():
            return {"context_id": value[0], "version": value[1] if len(value) > 1 else None}
        case _:
            reference = {"context_id": value["context_id"]}
            if value.get("version") is not None:
                reference["version"] = value["version"]
            return reference


def _normalize_objects(objects: Iterable[Any]) -> list[dict[str, Any]]:
    return [_object_reference(value) for value in objects]


def _validate_token(token: str) -> str:
    normalized_token = token.strip()
    if not normalized_token:
        raise ConfigError("auth_token is empty")
    if any(ord(character) < 33 or ord(character) == 127 for character in normalized_token):
        raise ConfigError("auth_token contains whitespace or control characters")
    return normalized_token


class InvariantClient:
    """Client for the decision API.

    ``auth_token`` is mandatory (sent as ``Authorization: Bearer``) unless ``allow_anonymous=True``,
    which exists only for local development against a server that does not enforce auth.

    ``fail_mode=BOUNDED_OFFLINE`` requires ``snapshot_public_key`` (base64 Ed25519 key, or a
    ``{key_id: key}`` mapping for rotation): the client then fetches and verifies ``/v1/snapshot`` and
    may serve cached ALLOWs without the server only while it holds a verified, unexpired snapshot whose
    epoch equals the cached decision's epoch. ``offline_lease_seconds`` further caps the lease.
    """

    def __init__(
        self,
        base_url: str,
        tenant_id: str,
        auth_token: str | None = None,
        fail_mode: FailMode | str = FailMode.ENFORCE,
        offline_lease_seconds: float = 60,
        *,
        allow_anonymous: bool = False,
        snapshot_public_key: str | bytes | Mapping[str, str | bytes] | None = None,
        timeout: float | httpx.Timeout | None = None,
        max_retries: int = 2,
        retry_backoff: float = 0.1,
        transport: httpx.BaseTransport | None = None,
        cache: DecisionCache | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        breaker_threshold: int = 5,
        breaker_recovery: float = 10.0,
        cache_max_entries: int = 10_000,
        durable_sessions: bool = False,
    ) -> None:
        if not tenant_id:
            raise ConfigError("tenant_id is required")
        if max_retries < 0:
            raise ConfigError("max_retries must be >= 0")
        try:
            self.fail_mode = FailMode(fail_mode)
        except ValueError as e:
            raise ConfigError(f"unknown fail_mode {fail_mode!r}") from e
        token = _validate_token(auth_token) if auth_token is not None else None
        if token is None and not allow_anonymous:
            raise ConfigError(
                "auth_token is required (every API call is bearer-authenticated); "
                "pass allow_anonymous=True only for local development"
            )
        self._snapshot_keys = load_public_keys(snapshot_public_key) if snapshot_public_key else None
        if self.fail_mode is FailMode.BOUNDED_OFFLINE and self._snapshot_keys is None:
            raise ConfigError(
                "fail_mode=BOUNDED_OFFLINE requires snapshot_public_key: without a verifiable signed "
                "policy snapshot the client cannot safely serve anything offline"
            )

        self.base_url = base_url.rstrip("/")
        self.tenant_id = tenant_id
        self.offline_lease_seconds = offline_lease_seconds
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self._clock = clock
        self._wall_clock = wall_clock
        self._sleep = sleep
        self.cache = (
            cache
            if cache is not None
            else DecisionCache(clock=clock, wall_clock=wall_clock, max_entries=cache_max_entries)
        )
        self.session_taint = SessionTaint()
        #: opt-in: report session exposures to the server so they survive a restart and a revocation can
        #: flag the session (``needs_reset``). See ``SessionTaint`` and ``docs/lifecycle.md``.
        self.durable_sessions = durable_sessions
        if durable_sessions:
            self.session_taint.bind(self)
        self.breaker: CircuitBreaker | None = (
            CircuitBreaker(breaker_threshold, breaker_recovery, clock=clock)
            if breaker_threshold > 0
            else None
        )
        self._lock = threading.RLock()
        self._last_success: float | None = None
        self._policy_version = ""
        self._snapshot: Snapshot | None = None
        self._next_snapshot_attempt = 0.0
        self.last_snapshot_error: SnapshotError | None = None
        self._has_token = token is not None
        headers = {"X-Tenant-Id": tenant_id, "Accept": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        self._http = httpx.Client(
            base_url=self.base_url,
            headers=headers,
            timeout=DEFAULT_TIMEOUT if timeout is None else timeout,
            transport=transport,
            follow_redirects=False,
        )

    def __repr__(self) -> str:
        return (
            f"InvariantClient(base_url={self.base_url!r}, tenant_id={self.tenant_id!r}, "
            f"fail_mode={self.fail_mode.value}, authenticated={self._has_token})"
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _backoff(self, attempt: int) -> None:
        """Exponential backoff with full jitter."""
        cap = self.retry_backoff * (2**attempt)
        self._sleep(random.uniform(0, cap))

    def _request(self, method: str, path: str, *, retries: int | None = None, **kw: Any) -> Any:
        """Send a request. Only idempotent calls (GET, authorize) are retried.

        ``retries`` defaults to ``max_retries`` for GET and 0 otherwise; ``authorize`` passes it
        explicitly. Retries cover transport errors and 429/502/503/504, with jittered backoff.
        """
        if "json" in kw:
            payload = kw.pop("json")
            try:
                content = _json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
            except (TypeError, ValueError) as e:
                raise InvalidRequestError(f"request body is not JSON-serialisable: {e}") from e
            if len(content) > MAX_REQUEST_BYTES:
                raise RequestTooLargeError(len(content), MAX_REQUEST_BYTES)
            kw["content"] = content
            kw["headers"] = {**kw.get("headers", {}), "Content-Type": "application/json"}
        if retries is None:
            retries = self.max_retries if method.upper() == "GET" else 0

        attempt = 0
        while True:
            err: AlesError | None = None
            response: httpx.Response | None = None
            try:
                response = self._http.request(method, path, **kw)
            except httpx.TimeoutException as e:
                err = AlesTimeoutError(f"timeout calling {path}: {e!r}")
                err.__cause__ = e
            except httpx.TransportError as e:
                err = AlesConnectionError(str(e) or repr(e))
                err.__cause__ = e
            else:
                if response.status_code in RETRYABLE_STATUS:
                    err = ServerUnavailableError(response.status_code, _body(response), str(response.url))
            if err is None:
                break
            if attempt >= retries:
                raise err
            self._backoff(attempt)
            attempt += 1

        assert response is not None
        if response.status_code >= 400:
            body = _body(response)
            url = str(response.url)
            if response.status_code in (401, 403):
                if response.status_code == 403 and "tenant" in AlesHTTPError(403, body).detail.lower():
                    raise TenantMismatchError(403, body, url, self.tenant_id)
                raise AuthError(response.status_code, body, url)
            raise AlesHTTPError(response.status_code, body, url)
        with self._lock:
            self._last_success = self._clock()
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as e:
            raise ResponseError(f"non-JSON response from {path}") from e

    @property
    def breaker_state(self) -> BreakerState | None:
        """Circuit breaker state for metrics (``None`` when the breaker is disabled)."""
        return self.breaker.state if self.breaker is not None else None

    @property
    def snapshot(self) -> Snapshot | None:
        """The currently held verified snapshot (may be expired; see :meth:`snapshot_valid`)."""
        with self._lock:
            return self._snapshot

    def snapshot_valid(self) -> bool:
        with self._lock:
            snap = self._snapshot
        return snap is not None and snap.valid_at(self._clock(), self.offline_lease_seconds)

    def lease_ok(self) -> bool:
        """Is the client currently entitled to serve decisions without the server?

        BOUNDED_OFFLINE: a verified, unexpired policy snapshot is held. Other modes: the last
        successful server contact is younger than ``offline_lease_seconds`` (informational only).
        """
        if self.fail_mode is FailMode.BOUNDED_OFFLINE:
            return self.snapshot_valid()
        with self._lock:
            last = self._last_success
        return last is not None and (self._clock() - last) < self.offline_lease_seconds

    def refresh_snapshot(self, *, retries: int | None = None) -> Snapshot:
        """Fetch ``GET /v1/snapshot`` and verify its Ed25519 signature.

        On any verification failure the previously held snapshot is discarded (fail closed) and
        :class:`SnapshotError` is raised.
        """
        if self._snapshot_keys is None:
            raise ConfigError("snapshot_public_key is not configured")
        data = self._request("GET", "/v1/snapshot", retries=retries)
        received = self._clock()
        try:
            snap = verify_snapshot(
                data,
                keys=self._snapshot_keys,
                tenant_id=self.tenant_id,
                received_at=received,
                wall_now=self._wall_clock(),
            )
            with self._lock:
                previous = self._snapshot
                if previous is not None and snap.revocation_epoch < previous.revocation_epoch:
                    raise SnapshotError(
                        "epoch_regression",
                        f"epoch {snap.revocation_epoch} < previously accepted {previous.revocation_epoch}",
                    )
        except SnapshotError as e:
            with self._lock:
                self._snapshot = None
                self.last_snapshot_error = e
            raise
        with self._lock:
            self._snapshot = snap
            self.last_snapshot_error = None
        self.cache.invalidate_if_epoch_advanced(snap.revocation_epoch)
        return snap

    def _maybe_refresh_snapshot(self, observed_epoch: int | None = None) -> None:
        """Opportunistic refresh: no snapshot, older than half its lease, or epoch moved on."""
        if self.fail_mode is not FailMode.BOUNDED_OFFLINE:
            return
        if self.breaker is not None and self.breaker.is_open():
            return  # server known-down: do not hammer it for a snapshot either
        now = self._clock()
        with self._lock:
            snap = self._snapshot
            if now < self._next_snapshot_attempt:
                return
        lease = (
            self.offline_lease_seconds
            if snap is None
            else min(snap.effective_lease, self.offline_lease_seconds)
        )
        need = (
            snap is None
            or (now - snap.received_at) >= lease / 2
            or (observed_epoch is not None and observed_epoch != snap.revocation_epoch)
        )
        if not need:
            return
        try:
            self.refresh_snapshot(retries=0)
        except (AlesConnectionError, ServerUnavailableError):
            self._note_snapshot_failure()
        except SnapshotError as e:
            log.warning("policy snapshot rejected: %s", e)
            self._note_snapshot_failure()
        except AlesHTTPError as e:
            if isinstance(e, AuthError):
                raise
            log.warning("snapshot fetch failed: %s", e)
            self._note_snapshot_failure()

    def _note_snapshot_failure(self) -> None:
        with self._lock:
            self._next_snapshot_attempt = self._clock() + SNAPSHOT_RETRY_INTERVAL

    def register_source(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        data = self._request("POST", "/v1/sources", json=dict(envelope))
        return data or _ref(envelope)

    def register_derivation(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        data = self._request("POST", "/v1/derivations", json=dict(envelope))
        return data or _ref(envelope)

    def submit_revocation(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """Submit a RevocationEvent. Missing event_id/tenant_id/effective_at are filled in."""
        ev = dict(event)
        ev.setdefault("event_id", str(uuid.uuid4()))
        ev.setdefault("tenant_id", self.tenant_id)
        ev.setdefault("effective_at", now_iso())
        data = self._request("POST", "/v1/revocations", json=ev)
        epoch = data.get("revocation_epoch")
        if epoch is not None:
            self.cache.invalidate_if_epoch_advanced(int(epoch))
        return data

    def authorize(
        self,
        principal: Mapping[str, str],
        purpose: str,
        objects: Iterable[Any],
        agent_id: str | None = None,
        session_id: str | None = None,
        tools: list[str] | None = None,
        risk: str | None = None,
        issuer: str | None = None,
    ) -> AuthorizeResult:
        """``POST /v1/authorize`` for ``principal`` (decision cache and fail modes apply).

        ``issuer`` (or ``principal['issuer']``) names the identity provider that vouches for ``principal['id']`` (the OIDC ``iss``), so
        scopes written as ``iss:<issuer>:<id>`` can tell two systems' "alice" apart. Group membership is
        resolved by the server, never sent by the client. The decision cache key carries no issuer, so a
        request with an issuer is never served from, nor stored in, the cache (like ``tools`` / ``risk``).
        """
        objs = _normalize_objects(objects)
        if not objs:
            raise InvalidRequestError("authorize requires at least one object")
        try:
            pid = principal["id"]
        except (KeyError, TypeError) as e:
            raise InvalidRequestError("principal must be a mapping with an 'id'") from e
        principal_type = principal.get("type", "user")
        if issuer is None:
            issuer = principal.get("issuer")
        bounded = self.fail_mode is FailMode.BOUNDED_OFFLINE

        if bounded:
            self._maybe_refresh_snapshot()
        with self._lock:
            policy_version = self._policy_version
        keys = [
            make_key(
                self.tenant_id,
                principal_type,
                pid,
                purpose,
                o["context_id"],
                o.get("version"),
                policy_version,
                agent_id,
            )
            for o in objs
        ]
        # tools/risk change what policy may decide, and the cache key does not carry them: a scoped
        # request must never be answered from (or populate) the unscoped decision cache.
        scoped = bool(tools) or bool(risk) or issuer is not None
        if policy_version and not scoped and (not bounded or self.snapshot_valid()):
            epochs = [self.cache.get(k) for k in keys]
            if all(e is not None for e in epochs) and (
                not bounded or self._epochs_match_snapshot(epochs, policy_version)
            ):
                return self._cached_result(objs, epochs, policy_version, from_offline=False)

        body: dict[str, Any] = {
            "tenant_id": self.tenant_id,
            "principal": {"type": principal_type, "id": pid},
            "purpose": purpose,
            "objects": objs,
        }
        if issuer is not None:
            body["principal"]["issuer"] = issuer
        if agent_id is not None:
            body["agent_id"] = agent_id
        if session_id is not None:
            body["session_id"] = session_id

        if tools:
            body["tools"] = list(tools)
        if risk:
            body["risk"] = risk

        brk = self.breaker
        if brk is not None and not brk.allow():
            return self._offline_result(objs, keys, use_cache=not scoped)  # open: fail fast, no I/O
        try:
            data = self._request("POST", "/v1/authorize", json=body, retries=self.max_retries)
        except (AlesConnectionError, ServerUnavailableError):
            if brk is not None:
                brk.record_failure()
            return self._offline_result(objs, keys, use_cache=not scoped)
        except AlesHTTPError:
            if brk is not None:
                brk.record_success()  # the server answered: transport is healthy
            raise
        except BaseException:
            if brk is not None:
                brk.abandon()
            raise
        if brk is not None:
            brk.record_success()

        result = AuthorizeResult.from_response(data)
        with self._lock:
            if self._policy_version and self._policy_version != result.policy_version:
                self.cache.clear()  # policy changed: nothing decided under the old one may be reused
            self._policy_version = result.policy_version
            if self._snapshot is not None and self._snapshot.policy_version != result.policy_version:
                # The held snapshot was signed under another policy: it can no longer vouch for anything
                # decided now. Drop it (fail closed); it is re-fetched below.
                self._snapshot = None
        self.cache.invalidate_if_epoch_advanced(result.revocation_epoch)
        for o in result.objects:
            if o.decision != "ALLOW" or scoped:
                continue
            spec = _spec_for_verdict(objs, o)
            if spec is None:
                continue
            k = make_key(
                self.tenant_id,
                principal_type,
                pid,
                purpose,
                o.context_id,
                spec.get("version"),
                result.policy_version,
                agent_id,
            )
            # Per-object bound, else the response-level one (older/odd servers). An unparseable bound is
            # not cacheable: fail closed rather than guess.
            raw = o.valid_until if o.valid_until is not None else result.valid_until
            try:
                until = _parse_rfc3339(raw) if raw is not None else None
            except ValueError:
                continue
            self.cache.put(k, o.decision, result.revocation_epoch, valid_until=until)
        if bounded:
            self._maybe_refresh_snapshot(observed_epoch=result.revocation_epoch)
        return result

    def _epochs_match_snapshot(self, epochs: list[int | None], policy_version: str) -> bool:
        snap = self.snapshot
        return (
            snap is not None
            and snap.policy_version == policy_version
            and all(e == snap.revocation_epoch for e in epochs)
        )

    def _cached_result(
        self, objs: list[dict[str, Any]], epochs: list[int | None], policy_version: str, *, from_offline: bool
    ) -> AuthorizeResult:
        return AuthorizeResult(
            decision="ALLOW",
            reason=["OK"],
            revocation_epoch=max((e or 0) for e in epochs) if epochs else 0,
            policy_version=policy_version,
            trace_id="cache-" + uuid.uuid4().hex[:12],
            objects=[ObjectVerdict(o["context_id"], "ALLOW", ["OK"], o.get("version")) for o in objs],
            from_cache=True,
            offline=from_offline,
            lease_ok=self.lease_ok() if from_offline else None,
        )

    def _offline_result(
        self, objs: list[dict[str, Any]], keys: list[Any], *, use_cache: bool = True
    ) -> AuthorizeResult:
        """Server unreachable. Fail closed unless BOUNDED_OFFLINE holds a valid snapshot AND the cached
        ALLOW was issued at exactly the snapshot's epoch."""
        lease = self.lease_ok()
        snap = self.snapshot
        usable = (
            use_cache
            and self.fail_mode is FailMode.BOUNDED_OFFLINE
            and lease
            and snap is not None
            and snap.policy_version == self._policy_version
        )
        verdicts: list[ObjectVerdict] = []
        for o, k in zip(objs, keys, strict=True):
            hit = False
            if usable:
                assert snap is not None
                hit = self.cache.get(k) == snap.revocation_epoch
            verdicts.append(
                ObjectVerdict(
                    o["context_id"],
                    "ALLOW" if hit else "UNKNOWN",
                    ["OK"] if hit else ["POLICY_SNAPSHOT_STALE"],
                    o.get("version"),
                )
            )
        all_ok = bool(verdicts) and all(v.decision == "ALLOW" for v in verdicts)
        return AuthorizeResult(
            decision="ALLOW" if all_ok else "UNKNOWN",
            reason=["OK"] if all_ok else ["POLICY_SNAPSHOT_STALE"],
            revocation_epoch=self.cache.latest_epoch,
            policy_version=self._policy_version,
            trace_id="offline-" + uuid.uuid4().hex[:12],
            objects=verdicts,
            from_cache=all_ok,
            offline=True,
            lease_ok=lease,
        )

    def lineage(self, context_id: str) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/v1/lineage/{urllib.parse.quote(context_id, safe='')}",
            params={"tenant_id": self.tenant_id},
        )

    def verify(self, adapter: str, mode: str = "strict") -> dict[str, Any]:
        return self._request(
            "POST", "/v1/verify", json={"tenant_id": self.tenant_id, "adapter": adapter, "mode": mode}
        )

    def authorize_handoff(self, from_workload: str, to_workload: str, purpose: str) -> dict[str, Any]:
        """``POST /v1/handoffs``: may ``from_workload`` hand work to ``to_workload`` for ``purpose``?"""
        return self._request(
            "POST",
            "/v1/handoffs",
            json={"from_workload": from_workload, "to_workload": to_workload, "purpose": purpose},
        )

    def authorize_release(
        self,
        principal: Mapping[str, str],
        action: str,
        destination: str,
        purpose: str,
        objects: Iterable[Any],
        workload: str | None = None,
        session_id: str | None = None,
    ) -> ReleaseReceipt:
        """``POST /v1/releases``: authorize an outward ``action`` to ``destination`` right before executing it.

        Never cached and never retried (each call mints a receipt). Under ENFORCE / BOUNDED_OFFLINE / WARN a
        non-ALLOW receipt raises :class:`ReleaseDenied` (HUMAN_REVIEW raises :class:`HumanReviewPending`, like
        handoffs); OBSERVE returns it. An unreachable or undeployed gate is UNKNOWN and goes through the same
        fail mode (a synthesised receipt with ``synthesised=True``). The receipt bounds, but cannot eliminate,
        the race between this check and the external side effect.
        """
        objs = _normalize_objects(objects)
        if not objs:
            raise InvalidRequestError("authorize_release requires at least one object")
        try:
            pid = principal["id"]
        except (KeyError, TypeError) as e:
            raise InvalidRequestError("principal must be a mapping with an 'id'") from e
        body: dict[str, Any] = {
            "principal": {"type": principal.get("type", "user"), "id": pid},
            "action": action,
            "destination": destination,
            "purpose": purpose,
            "objects": objs,
        }
        if workload is not None:
            body["workload"] = workload
        if session_id is not None:
            body["session_id"] = session_id
        try:
            receipt = ReleaseReceipt.from_response(
                self._request("POST", "/v1/releases", json=body, retries=0)
            )
        except AlesHTTPError as e:
            if e.status_code == 404 or isinstance(e, ServerUnavailableError):
                receipt = self._unreachable_receipt(
                    "RELEASE_ENDPOINT_UNAVAILABLE" if e.status_code == 404 else "RELEASE_SERVER_UNAVAILABLE"
                )
            else:
                raise
        except AlesConnectionError:
            receipt = self._unreachable_receipt("RELEASE_SERVER_UNAVAILABLE")
        if receipt.decision == "HUMAN_REVIEW" and self.fail_mode in (
            FailMode.ENFORCE,
            FailMode.BOUNDED_OFFLINE,
        ):
            raise HumanReviewPending([o["context_id"] for o in objs], receipt.reason)
        if not resolve(receipt.decision, self.fail_mode, None, None).allow:
            raise ReleaseDenied(receipt.reason or [receipt.decision], receipt)
        return receipt

    def _unreachable_receipt(self, code: str) -> ReleaseReceipt:
        return ReleaseReceipt(
            receipt_id="",
            decision="UNKNOWN",
            reason=["RELEASE_DENIED", code],
            valid_until=now_iso(),
            revocation_epoch=self.cache.latest_epoch,
            policy_version=self._policy_version,
            synthesised=True,
        )

    def report_session_exposures(
        self,
        session_id: str,
        principal: Mapping[str, str],
        exposures: Iterable[Any],
        workload: str | None = None,
    ) -> dict[str, Any]:
        """``POST /v1/sessions/{id}/exposures``: tell the server this session was served these objects.

        ``exposures`` are context ids or ``(context_id, version)`` pairs (``None`` version = any version).
        An idempotent upsert, so the normal retry policy applies."""
        items: list[dict[str, Any]] = []
        for x in exposures:
            context_id, version = (x, None) if isinstance(x, str) else (x[0], x[1])
            items.append({"context_id": context_id, "version": version})
        if not items:
            raise InvalidRequestError("report_session_exposures requires at least one exposure")
        try:
            pid = principal["id"]
        except (KeyError, TypeError) as e:
            raise InvalidRequestError("principal must be a mapping with an 'id'") from e
        body: dict[str, Any] = {
            "principal": {"type": principal.get("type", "user"), "id": pid},
            "exposures": items,
        }
        if workload is not None:
            body["workload"] = workload
        return self._request(
            "POST", f"/v1/sessions/{urllib.parse.quote(session_id, safe='')}/exposures", json=body
        )

    def session_exposures(self, session_id: str) -> dict[str, Any]:
        """``GET /v1/sessions/{id}``: the server's view (``exposure_count``, ``generation``, ``needs_reset``)."""
        return self._request("GET", f"/v1/sessions/{urllib.parse.quote(session_id, safe='')}")

    def reset_session(self, session_id: str) -> dict[str, Any]:
        """``POST /v1/sessions/{id}/reset``: record that the host reset the session (bumps its generation).
        Also clears the local taint record. The host performs the actual reset."""
        result = self._request("POST", f"/v1/sessions/{urllib.parse.quote(session_id, safe='')}/reset")
        self.session_taint.clear(session_id)
        return result

    def healthz(self) -> dict[str, Any]:
        return self._request("GET", "/v1/healthz")


def _body(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text


def _ref(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {"context_id": envelope["context_id"], "object_version": envelope["object_version"]}
