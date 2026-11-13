"""Synchronous HTTP client for the ALES INVARIANT decision API."""

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
    InvalidRequestError,
    RequestTooLargeError,
    ResponseError,
    ServerUnavailableError,
    SnapshotError,
    TenantMismatchError,
)
from .fail_modes import FailMode
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

    def verdict_for(self, context_id: str) -> ObjectVerdict | None:
        for o in self.objects:
            if o.context_id == context_id:
                return o
        return None

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


def _parse_rfc3339(value: str) -> float:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("valid_until has no timezone")
    return dt.timestamp()


def _normalize_objects(objects: Iterable[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for o in objects:
        if isinstance(o, str):
            out.append({"context_id": o})
        elif isinstance(o, tuple):
            out.append({"context_id": o[0], "version": o[1] if len(o) > 1 else None})
        else:
            d: dict[str, Any] = {"context_id": o["context_id"]}
            if o.get("version") is not None:
                d["version"] = o["version"]
            out.append(d)
    return out


def _validate_token(token: str) -> str:
    t = token.strip()
    if not t:
        raise ConfigError("auth_token is empty")
    if any(ord(c) < 33 or ord(c) == 127 for c in t):
        raise ConfigError("auth_token contains whitespace or control characters")
    return t


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
        self.cache = cache if cache is not None else DecisionCache(clock=clock, wall_clock=wall_clock, max_entries=cache_max_entries)
        self.session_taint = SessionTaint()
        self.breaker: CircuitBreaker | None = (
            CircuitBreaker(breaker_threshold, breaker_recovery, clock=clock) if breaker_threshold > 0 else None
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

    # -- lifecycle ---------------------------------------------------------------------------
    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- transport ---------------------------------------------------------------------------
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
            resp: httpx.Response | None = None
            try:
                resp = self._http.request(method, path, **kw)
            except httpx.TimeoutException as e:
                err = AlesTimeoutError(f"timeout calling {path}: {e!r}")
                err.__cause__ = e
            except httpx.TransportError as e:
                err = AlesConnectionError(str(e) or repr(e))
                err.__cause__ = e
            else:
                if resp.status_code in RETRYABLE_STATUS:
                    err = ServerUnavailableError(resp.status_code, _body(resp), str(resp.url))
            if err is None:
                break
            if attempt >= retries:
                raise err
            self._backoff(attempt)
            attempt += 1

        assert resp is not None
        if resp.status_code >= 400:
            body = _body(resp)
            url = str(resp.url)
            if resp.status_code in (401, 403):
                if resp.status_code == 403 and "tenant" in AlesHTTPError(403, body).detail.lower():
                    raise TenantMismatchError(403, body, url, self.tenant_id)
                raise AuthError(resp.status_code, body, url)
            raise AlesHTTPError(resp.status_code, body, url)
        with self._lock:
            self._last_success = self._clock()
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError as e:
            raise ResponseError(f"non-JSON response from {path}") from e

    @property
    def breaker_state(self) -> BreakerState | None:
        """Circuit breaker state for metrics (``None`` when the breaker is disabled)."""
        return self.breaker.state if self.breaker is not None else None

    # -- offline lease / snapshot --------------------------------------------------------------
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
                prev = self._snapshot
                if prev is not None and snap.revocation_epoch < prev.revocation_epoch:
                    raise SnapshotError(
                        "epoch_regression",
                        f"epoch {snap.revocation_epoch} < previously accepted {prev.revocation_epoch}",
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
        lease = self.offline_lease_seconds if snap is None else min(snap.effective_lease, self.offline_lease_seconds)
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

    # -- registration ------------------------------------------------------------------------
    def register_source(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        data = self._request("POST", "/v1/sources", json=dict(envelope))
        return data or _ref(envelope)

    def register_derivation(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        data = self._request("POST", "/v1/derivations", json=dict(envelope))
        return data or _ref(envelope)

    # -- revocation --------------------------------------------------------------------------
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

    # -- authorize ---------------------------------------------------------------------------
    def authorize(
        self,
        principal: Mapping[str, str],
        purpose: str,
        objects: Iterable[Any],
        agent_id: str | None = None,
        session_id: str | None = None,
        tools: list[str] | None = None,
        risk: str | None = None,
    ) -> AuthorizeResult:
        objs = _normalize_objects(objects)
        if not objs:
            raise InvalidRequestError("authorize requires at least one object")
        try:
            pid = principal["id"]
        except (KeyError, TypeError) as e:
            raise InvalidRequestError("principal must be a mapping with an 'id'") from e
        ptype = principal.get("type", "user")
        bounded = self.fail_mode is FailMode.BOUNDED_OFFLINE

        if bounded:
            self._maybe_refresh_snapshot()
        with self._lock:
            policy_version = self._policy_version
        keys = [
            make_key(self.tenant_id, ptype, pid, purpose, o["context_id"], o.get("version"), policy_version)
            for o in objs
        ]
        # tools/risk change what policy may decide, and the cache key does not carry them: a scoped
        # request must never be answered from (or populate) the unscoped decision cache.
        scoped = bool(tools) or bool(risk)
        if policy_version and not scoped and (not bounded or self.snapshot_valid()):
            epochs = [self.cache.get(k) for k in keys]
            if all(e is not None for e in epochs) and (not bounded or self._epochs_match_snapshot(epochs)):
                return self._cached_result(objs, epochs, policy_version, from_offline=False)

        body: dict[str, Any] = {
            "tenant_id": self.tenant_id,
            "principal": {"type": ptype, "id": pid},
            "purpose": purpose,
            "objects": objs,
        }
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
        self.cache.invalidate_if_epoch_advanced(result.revocation_epoch)
        for o in result.objects:
            if o.decision != "ALLOW" or scoped:
                continue
            spec = next((x for x in objs if x["context_id"] == o.context_id), None)
            if spec is None:
                continue
            k = make_key(
                self.tenant_id, ptype, pid, purpose, o.context_id, spec.get("version"), result.policy_version
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

    def _epochs_match_snapshot(self, epochs: list[int | None]) -> bool:
        snap = self.snapshot
        return snap is not None and all(e == snap.revocation_epoch for e in epochs)

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
        usable = use_cache and self.fail_mode is FailMode.BOUNDED_OFFLINE and lease and snap is not None
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

    # -- queries -----------------------------------------------------------------------------
    def lineage(self, context_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/lineage/{urllib.parse.quote(context_id, safe='')}", params={"tenant_id": self.tenant_id})

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

    def healthz(self) -> dict[str, Any]:
        return self._request("GET", "/v1/healthz")


def _body(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text


def _ref(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {"context_id": envelope["context_id"], "object_version": envelope["object_version"]}
