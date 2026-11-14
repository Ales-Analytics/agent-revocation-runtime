"""HTTP client for external policy providers (spec v0.4).

Configuration: ``ALES_POLICY_PROVIDERS`` is a JSON list of objects
``{"name", "url", "required": bool, "kind": "opa"|"cedar"|"custom", "timeout_s": 3,
"auth_token_env": "ENVVAR"?, "policy_path"?}``. Tokens are referenced by environment-variable NAME only
(never inline). Any malformed entry is a startup ``ConfigError`` (fail closed). In production every
provider must use ``https`` and carry ``auth_token_env``.

Request translation per ``kind`` (the provider request is the neutral ``PolicyProviderRequest``):

* ``custom``: ``POST url`` with the neutral request verbatim; the body must be a ``PolicyProviderResult``.
* ``opa``: ``POST url`` with ``{"input": <request>}`` (OPA Data API). ``policy_path`` (e.g.
  ``ales/release/allow``) is appended as ``<url>/v1/data/<policy_path>`` when given; otherwise ``url`` is the
  full data path. The answer is ``{"result": X}``: ``X`` may be a **bool** (``true`` = ALLOW, ``false`` =
  DENY) or an **object**: with a ``decision`` key it is a full ``PolicyProviderResult`` (``provider`` and
  ``policy_revision`` default to the configured name / ``"unversioned"``), otherwise an ``allow`` boolean
  maps to ALLOW/DENY and optional ``obligations``, ``policy_revision``, ``valid_until``, ``explanation_ref``
  are honoured. A missing ``result`` (undefined rule) is malformed, hence UNAVAILABLE, never ALLOW.
* ``cedar``: a Cedar-style local authorization service. One ``POST url`` per resource with
  ``{"principal": 'User::"id"', "action": 'Action::"name"', "resource": 'Context::"id"', "context": {...}}``
  (``Agent``/``Service`` for non-user principals). The answer ``{"decision": "Allow"|"Deny"}`` (any case) is
  mapped per resource; ALL resources must be allowed. ``policy_revision`` is read from the answer when present.

Everything that is not a well-formed answer (timeout, connection error, redirect, non-200, oversize or
non-JSON body, schema violation) is reported as ``None`` = unavailable. Redirects are never followed and
responses are capped at :data:`MAX_RESPONSE_BYTES`.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any
from urllib.parse import urlsplit

import httpx
from ales_core import (
    CallMeta,
    PolicyProviderRequest,
    PolicyProviderResult,
    ProviderConfig,
    ProviderKind,
)
from pydantic import ValidationError

from .config import ConfigError

log = logging.getLogger("ales.server.providers")

MAX_RESPONSE_BYTES = 256 * 1024
MAX_PROVIDERS = 16
MAX_WORKERS = 8
MAX_CEDAR_RESOURCES = 25

ProviderCallResult = tuple[PolicyProviderResult | None, CallMeta]


def _is_loopback(host: str | None) -> bool:
    return host in ("localhost", "127.0.0.1", "::1")


def parse_providers(
    raw: str | None, *, production: bool = False, env: Mapping[str, str] | None = None
) -> tuple[ProviderConfig, ...]:
    """Parse ``ALES_POLICY_PROVIDERS``. Unset/blank = no providers. Everything else invalid = ``ConfigError``."""
    if raw is None or not raw.strip():
        return ()
    e = os.environ if env is None else env
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ConfigError(f"ALES_POLICY_PROVIDERS is not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ConfigError("ALES_POLICY_PROVIDERS must be a JSON list of provider objects")
    if len(data) > MAX_PROVIDERS:
        raise ConfigError(f"ALES_POLICY_PROVIDERS: at most {MAX_PROVIDERS} providers")
    configs: list[ProviderConfig] = []
    for i, item in enumerate(data):
        try:
            cfg = ProviderConfig.model_validate(item)
        except ValidationError as exc:
            msgs = "; ".join(f"{'.'.join(str(x) for x in d['loc'])}: {d['msg']}" for d in exc.errors())
            raise ConfigError(f"ALES_POLICY_PROVIDERS[{i}] invalid: {msgs}") from exc
        if cfg.name in {c.name for c in configs}:
            raise ConfigError(f"ALES_POLICY_PROVIDERS: duplicate provider name {cfg.name!r}")
        if cfg.auth_token_env is not None and not e.get(cfg.auth_token_env, "").strip():
            raise ConfigError(
                f"provider {cfg.name!r}: auth_token_env {cfg.auth_token_env!r} is not set in the environment"
            )
        if production:
            parts = urlsplit(cfg.url)
            if parts.scheme != "https" and not _is_loopback(parts.hostname):
                raise ConfigError(f"provider {cfg.name!r}: production requires an https URL")
            if cfg.auth_token_env is None and not _is_loopback(parts.hostname):
                raise ConfigError(f"provider {cfg.name!r}: production requires auth_token_env (authenticated calls)")
        configs.append(cfg)
    return tuple(configs)


# ------------------------------------------------------------------------------- response mapping
def _opa_result(body: Any, cfg: ProviderConfig) -> PolicyProviderResult | None:
    if not isinstance(body, dict) or "result" not in body:
        return None  # undefined rule / wrong path: never an implicit ALLOW
    x = body["result"]
    if isinstance(x, bool):
        return PolicyProviderResult(
            decision="ALLOW" if x else "DENY", provider=cfg.name, policy_revision="unversioned"
        )
    if not isinstance(x, dict):
        return None
    obj = dict(x)
    obj.setdefault("provider", cfg.name)
    obj.setdefault("policy_revision", "unversioned")
    if "decision" not in obj:
        allow = obj.get("allow")
        if not isinstance(allow, bool):
            return None
        obj["decision"] = "ALLOW" if allow else "DENY"
    if "explanation_ref" not in obj and isinstance(body.get("decision_id"), str):
        obj["explanation_ref"] = body["decision_id"]
    return PolicyProviderResult.model_validate(obj)


_CEDAR_TYPE = {"user": "User", "agent": "Agent", "service": "Service"}


def _uid(kind: str, ident: str) -> str:
    return f"{kind}::{json.dumps(ident, ensure_ascii=False)}"


def _cedar_request(req: PolicyProviderRequest, context_id: str) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "purpose": req.purpose,
        "destination": req.destination,
        "acting_workload": req.acting_workload,
        "verified_context": req.verified_context,
    }
    return {
        "principal": _uid(_CEDAR_TYPE.get(req.principal.type, "User"), req.principal.id),
        "action": _uid("Action", req.action),
        "resource": _uid("Context", context_id),
        "context": ctx,
    }


def _cedar_result(bodies: list[Any], cfg: ProviderConfig) -> PolicyProviderResult | None:
    revision = "unversioned"
    allow = True
    for b in bodies:
        if not isinstance(b, dict) or not isinstance(b.get("decision"), str):
            return None
        d = b["decision"].strip().lower()
        if d not in ("allow", "deny"):
            return None
        allow = allow and d == "allow"
        if isinstance(b.get("policy_revision"), str) and b["policy_revision"]:
            revision = b["policy_revision"][:256]
    return PolicyProviderResult(decision="ALLOW" if allow else "DENY", provider=cfg.name, policy_revision=revision)


# --------------------------------------------------------------------------------------- the runner
class ProviderRunner:
    """Calls every configured provider in parallel (bounded threads), outside any database transaction."""

    def __init__(
        self,
        configs: tuple[ProviderConfig, ...],
        *,
        env: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        max_workers: int = MAX_WORKERS,
    ) -> None:
        self.configs = configs
        self._env = os.environ if env is None else env
        self._max_workers = max(1, min(max_workers, MAX_WORKERS))
        self._http = httpx.Client(
            follow_redirects=False,
            transport=transport,
            limits=httpx.Limits(max_connections=32, max_keepalive_connections=8),
        )

    def close(self) -> None:
        self._http.close()

    # -- one HTTP exchange -------------------------------------------------------------------
    def _post(self, cfg: ProviderConfig, url: str, payload: dict[str, Any], deadline: float) -> Any:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if cfg.auth_token_env is not None:
            token = self._env.get(cfg.auth_token_env, "").strip()
            if not token:
                raise _Unavailable("auth_token_missing")
            headers["Authorization"] = f"Bearer {token}"
        content = json.dumps(payload, separators=(",", ":"), allow_nan=False, default=str).encode("utf-8")
        with self._http.stream(
            "POST", url, content=content, headers=headers, timeout=httpx.Timeout(cfg.timeout_s)
        ) as resp:
            if resp.status_code != 200:
                raise _Unavailable(f"http_{resp.status_code}")
            buf = bytearray()
            for chunk in resp.iter_bytes():
                buf += chunk
                if len(buf) > MAX_RESPONSE_BYTES:
                    raise _Unavailable("oversize")
                if time.monotonic() > deadline:
                    raise _Unavailable("timeout")
        try:
            return json.loads(bytes(buf))
        except ValueError as exc:
            raise _Unavailable("malformed") from exc

    def _call_one(self, cfg: ProviderConfig, req: PolicyProviderRequest) -> ProviderCallResult:
        t0 = time.monotonic()
        deadline = t0 + cfg.timeout_s + 0.25
        err: str | None = None
        result: PolicyProviderResult | None = None
        try:
            result = self._dispatch(cfg, req, deadline)
            if result is None:
                err = "malformed"
        except _Unavailable as exc:
            err = str(exc)
        except httpx.TimeoutException:
            err = "timeout"
        except httpx.TransportError:
            err = "connect"
        except (ValidationError, ValueError, TypeError, KeyError):
            err = "malformed"
        except Exception:
            log.exception("policy provider %s failed unexpectedly", cfg.name)
            err = "error"
        ms = int((time.monotonic() - t0) * 1000)
        if result is not None:
            result = result.model_copy(update={"latency_ms": ms})
        return result, CallMeta(latency_ms=ms, error=err)

    def _dispatch(self, cfg: ProviderConfig, req: PolicyProviderRequest, deadline: float) -> PolicyProviderResult | None:
        if cfg.kind == ProviderKind.OPA:
            url = cfg.url
            if cfg.policy_path:
                url = url.rstrip("/") + "/v1/data/" + cfg.policy_path.strip("/")
            body = self._post(cfg, url, {"input": req.model_dump(mode="json")}, deadline)
            return _opa_result(body, cfg)
        if cfg.kind == ProviderKind.CEDAR:
            if len(req.resource_refs) > MAX_CEDAR_RESOURCES:
                raise _Unavailable("too_many_resources")
            bodies = [
                self._post(cfg, cfg.url, _cedar_request(req, r.context_id), deadline) for r in req.resource_refs
            ]
            return _cedar_result(bodies, cfg)
        body = self._post(cfg, cfg.url, req.model_dump(mode="json"), deadline)
        return PolicyProviderResult.model_validate(body)

    # -- all providers -----------------------------------------------------------------------
    def run(
        self, req: PolicyProviderRequest
    ) -> tuple[list[tuple[ProviderConfig, PolicyProviderResult | None]], dict[str, CallMeta]]:
        """Call every provider concurrently. Never raises: failures are ``None`` results plus ``CallMeta``."""
        pairs: list[tuple[ProviderConfig, PolicyProviderResult | None]] = []
        metas: dict[str, CallMeta] = {}
        if not self.configs:
            return pairs, metas
        ex = ThreadPoolExecutor(max_workers=min(self._max_workers, len(self.configs)), thread_name_prefix="ales-prov")
        try:
            futures: list[tuple[ProviderConfig, Future[ProviderCallResult]]] = [
                (c, ex.submit(self._call_one, c, req)) for c in self.configs
            ]
            for cfg, fut in futures:
                try:
                    result, meta = fut.result(timeout=cfg.timeout_s + 1.0)
                except FutureTimeout:
                    result, meta = None, CallMeta(latency_ms=int(cfg.timeout_s * 1000), error="timeout")
                pairs.append((cfg, result))
                metas[cfg.name] = meta
        finally:
            ex.shutdown(wait=False, cancel_futures=True)  # a stuck provider thread must not hold the request
        return pairs, metas


class _Unavailable(Exception):
    """Internal: the provider could not give a usable answer (message is a short stable code)."""
