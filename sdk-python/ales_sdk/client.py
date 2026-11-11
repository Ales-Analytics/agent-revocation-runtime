"""Synchronous HTTP client for the ALES INVARIANT decision API."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Self

import httpx

from .decision_cache import DecisionCache, make_key
from .envelope import now_iso
from .fail_modes import FailMode
from .session_taint import SessionTaint


class AlesError(Exception):
    """Base SDK error."""


class AlesHTTPError(AlesError):
    def __init__(self, status_code: int, body: Any, url: str = "") -> None:
        super().__init__(f"HTTP {status_code} from {url}: {body!r}")
        self.status_code = status_code
        self.body = body
        self.url = url


class AlesConnectionError(AlesError):
    """Server unreachable."""


@dataclass
class ObjectVerdict:
    context_id: str
    decision: str
    reason: list[str] = field(default_factory=list)
    version: str | None = None


@dataclass
class AuthorizeResult:
    decision: str
    reason: list[str]
    revocation_epoch: int
    policy_version: str
    trace_id: str
    objects: list[ObjectVerdict] = field(default_factory=list)
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
        return cls(
            decision=data["decision"],
            reason=list(data.get("reason", [])),
            revocation_epoch=int(data["revocation_epoch"]),
            policy_version=data["policy_version"],
            trace_id=data["trace_id"],
            objects=[
                ObjectVerdict(o["context_id"], o["decision"], list(o.get("reason", [])), o.get("version"))
                for o in data.get("objects", [])
            ],
        )




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


class InvariantClient:
    def __init__(
        self,
        base_url: str,
        tenant_id: str,
        auth_token: str | None = None,
        fail_mode: FailMode | str = FailMode.ENFORCE,
        offline_lease_seconds: float = 60,
        *,
        timeout: float = 5.0,
        transport: httpx.BaseTransport | None = None,
        cache: DecisionCache | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.tenant_id = tenant_id
        self.fail_mode = FailMode(fail_mode)
        self.offline_lease_seconds = offline_lease_seconds
        self._clock = clock
        self.cache = cache or DecisionCache(clock=clock)
        self.session_taint = SessionTaint()
        self._last_success: float | None = None
        self._policy_version = ""
        headers = {"X-Tenant-Id": tenant_id}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        self._http = httpx.Client(
            base_url=self.base_url, headers=headers, timeout=timeout, transport=transport
        )

    # -- lifecycle ---------------------------------------------------------------------------
    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- transport ---------------------------------------------------------------------------
    def _request(self, method: str, path: str, **kw: Any) -> Any:
        try:
            resp = self._http.request(method, path, **kw)
        except httpx.TransportError as e:
            raise AlesConnectionError(str(e)) from e
        if resp.status_code >= 400:
            try:
                body: Any = resp.json()
            except ValueError:
                body = resp.text
            raise AlesHTTPError(resp.status_code, body, str(resp.url))
        self._last_success = self._clock()
        if not resp.content:
            return {}
        return resp.json()

    def lease_ok(self) -> bool:
        """True if the last successful server contact is younger than the offline lease."""
        if self._last_success is None:
            return False
        return (self._clock() - self._last_success) < self.offline_lease_seconds

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
    ) -> AuthorizeResult:
        objs = _normalize_objects(objects)
        pid = principal["id"]
        keys = [make_key(o["context_id"], o.get("version"), pid, purpose, self._policy_version) for o in objs]

        use_fast_path = self.fail_mode is not FailMode.BOUNDED_OFFLINE or self.lease_ok()
        if use_fast_path and self._policy_version and all(self.cache.get(k) is not None for k in keys):
            return self._cached_result(objs, keys, from_offline=False)

        body: dict[str, Any] = {
            "tenant_id": self.tenant_id,
            "principal": {"type": principal.get("type", "user"), "id": pid},
            "purpose": purpose,
            "objects": objs,
        }
        if agent_id is not None:
            body["agent_id"] = agent_id
        if session_id is not None:
            body["session_id"] = session_id

        try:
            data = self._request("POST", "/v1/authorize", json=body)
        except AlesConnectionError:
            return self._offline_result(objs, keys)

        result = AuthorizeResult.from_response(data)
        self._policy_version = result.policy_version
        self.cache.invalidate_if_epoch_advanced(result.revocation_epoch)
        for o in result.objects:
            if o.decision != "ALLOW":
                continue
            spec = next((x for x in objs if x["context_id"] == o.context_id), None)
            if spec is None:
                continue
            k = make_key(o.context_id, spec.get("version"), pid, purpose, result.policy_version)
            self.cache.put(k, o.decision, result.revocation_epoch)
        return result

    def _cached_result(
        self, objs: list[dict[str, Any]], keys: list[Any], *, from_offline: bool
    ) -> AuthorizeResult:
        epoch = max((self.cache.get(k) or 0) for k in keys)
        return AuthorizeResult(
            decision="ALLOW",
            reason=["OK"],
            revocation_epoch=epoch,
            policy_version=self._policy_version,
            trace_id="cache-" + uuid.uuid4().hex[:12],
            objects=[ObjectVerdict(o["context_id"], "ALLOW", ["OK"], o.get("version")) for o in objs],
            from_cache=True,
            offline=from_offline,
            lease_ok=self.lease_ok() if from_offline else None,
        )

    def _offline_result(self, objs: list[dict[str, Any]], keys: list[Any]) -> AuthorizeResult:
        lease = self.lease_ok()
        use_cache = self.fail_mode is FailMode.BOUNDED_OFFLINE and lease
        verdicts: list[ObjectVerdict] = []
        for o, k in zip(objs, keys, strict=True):
            hit = use_cache and self.cache.get(k) is not None
            verdicts.append(
                ObjectVerdict(
                    o["context_id"],
                    "ALLOW" if hit else "UNKNOWN",
                    ["OK"] if hit else ["POLICY_SNAPSHOT_STALE"],
                    o.get("version"),
                )
            )
        all_ok = all(v.decision == "ALLOW" for v in verdicts)
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
        return self._request("GET", f"/v1/lineage/{context_id}", params={"tenant_id": self.tenant_id})

    def verify(self, adapter: str, mode: str = "strict") -> dict[str, Any]:
        return self._request(
            "POST", "/v1/verify", json={"tenant_id": self.tenant_id, "adapter": adapter, "mode": mode}
        )

    def healthz(self) -> dict[str, Any]:
        return self._request("GET", "/v1/healthz")


def _ref(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {"context_id": envelope["context_id"], "object_version": envelope["object_version"]}
