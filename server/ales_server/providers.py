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


def _validate_provider_connection(
    config: ProviderConfig, environment: Mapping[str, str], production: bool
) -> None:
    if config.auth_token_env is not None and not environment.get(config.auth_token_env, "").strip():
        raise ConfigError(
            f"provider {config.name!r}: auth_token_env {config.auth_token_env!r} is not set in the environment"
        )
    if not production:
        return
    address = urlsplit(config.url)
    if address.scheme != "https" and not _is_loopback(address.hostname):
        raise ConfigError(f"provider {config.name!r}: production requires an https URL")
    if config.auth_token_env is None and not _is_loopback(address.hostname):
        raise ConfigError(
            f"provider {config.name!r}: production requires auth_token_env (authenticated calls)"
        )


def parse_providers(
    raw: str | None, *, production: bool = False, env: Mapping[str, str] | None = None
) -> tuple[ProviderConfig, ...]:
    """Parse ``ALES_POLICY_PROVIDERS``. Unset/blank = no providers. Everything else invalid = ``ConfigError``."""
    if raw is None or not raw.strip():
        return ()
    environment = os.environ if env is None else env
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ConfigError(f"ALES_POLICY_PROVIDERS is not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ConfigError("ALES_POLICY_PROVIDERS must be a JSON list of provider objects")
    if len(data) > MAX_PROVIDERS:
        raise ConfigError(f"ALES_POLICY_PROVIDERS: at most {MAX_PROVIDERS} providers")
    configs: list[ProviderConfig] = []
    provider_names: set[str] = set()
    for index, item in enumerate(data):
        try:
            config = ProviderConfig.model_validate(item)
        except ValidationError as exc:
            validation_errors = "; ".join(
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}" for error in exc.errors()
            )
            raise ConfigError(f"ALES_POLICY_PROVIDERS[{index}] invalid: {validation_errors}") from exc
        if config.name in provider_names:
            raise ConfigError(f"ALES_POLICY_PROVIDERS: duplicate provider name {config.name!r}")
        _validate_provider_connection(config, environment, production)
        configs.append(config)
        provider_names.add(config.name)
    return tuple(configs)


def _opa_result(body: Any, cfg: ProviderConfig) -> PolicyProviderResult | None:
    if not isinstance(body, dict) or "result" not in body:
        return None  # undefined rule / wrong path: never an implicit ALLOW
    provider_result = body["result"]
    if isinstance(provider_result, bool):
        return PolicyProviderResult(
            decision="ALLOW" if provider_result else "DENY", provider=cfg.name, policy_revision="unversioned"
        )
    if not isinstance(provider_result, dict):
        return None
    result_fields = dict(provider_result)
    result_fields.setdefault("provider", cfg.name)
    result_fields.setdefault("policy_revision", "unversioned")
    if "decision" not in result_fields:
        allow = result_fields.get("allow")
        if not isinstance(allow, bool):
            return None
        result_fields["decision"] = "ALLOW" if allow else "DENY"
    if "explanation_ref" not in result_fields and isinstance(body.get("decision_id"), str):
        result_fields["explanation_ref"] = body["decision_id"]
    return PolicyProviderResult.model_validate(result_fields)


_CEDAR_TYPE = {"user": "User", "agent": "Agent", "service": "Service"}


def _uid(kind: str, ident: str) -> str:
    return f"{kind}::{json.dumps(ident, ensure_ascii=False)}"


def _cedar_request(req: PolicyProviderRequest, context_id: str) -> dict[str, Any]:
    context: dict[str, Any] = {
        "purpose": req.purpose,
        "destination": req.destination,
        "acting_workload": req.acting_workload,
        "verified_context": req.verified_context,
    }
    return {
        "principal": _uid(_CEDAR_TYPE.get(req.principal.type, "User"), req.principal.id),
        "action": _uid("Action", req.action),
        "resource": _uid("Context", context_id),
        "context": context,
    }


def _cedar_result(bodies: list[Any], cfg: ProviderConfig) -> PolicyProviderResult | None:
    revision = "unversioned"
    allow = True
    for body in bodies:
        if not isinstance(body, dict) or not isinstance(body.get("decision"), str):
            return None
        decision = body["decision"].strip().lower()
        if decision not in ("allow", "deny"):
            return None
        allow = allow and decision == "allow"
        if isinstance(body.get("policy_revision"), str) and body["policy_revision"]:
            revision = body["policy_revision"][:256]
    return PolicyProviderResult(
        decision="ALLOW" if allow else "DENY", provider=cfg.name, policy_revision=revision
    )


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
        ) as response:
            if response.status_code != 200:
                raise _Unavailable(f"http_{response.status_code}")
            response_bytes = bytearray()
            for chunk in response.iter_bytes():
                response_bytes += chunk
                if len(response_bytes) > MAX_RESPONSE_BYTES:
                    raise _Unavailable("oversize")
                if time.monotonic() > deadline:
                    raise _Unavailable("timeout")
        try:
            return json.loads(bytes(response_bytes))
        except ValueError as exc:
            raise _Unavailable("malformed") from exc

    def _call_one(self, cfg: ProviderConfig, req: PolicyProviderRequest) -> ProviderCallResult:
        started_at = time.monotonic()
        deadline = started_at + cfg.timeout_s + 0.25
        error: str | None = None
        result: PolicyProviderResult | None = None
        try:
            result = self._dispatch(cfg, req, deadline)
            if result is None:
                error = "malformed"
        except _Unavailable as exc:
            error = str(exc)
        except httpx.TimeoutException:
            error = "timeout"
        except httpx.TransportError:
            error = "connect"
        except (ValidationError, ValueError, TypeError, KeyError):
            error = "malformed"
        except Exception:
            log.exception("policy provider %s failed unexpectedly", cfg.name)
            error = "error"
        latency_ms = int((time.monotonic() - started_at) * 1000)
        if result is not None:
            result = result.model_copy(update={"latency_ms": latency_ms})
        return result, CallMeta(latency_ms=latency_ms, error=error)

    def _dispatch(
        self, cfg: ProviderConfig, req: PolicyProviderRequest, deadline: float
    ) -> PolicyProviderResult | None:
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
                self._post(cfg, cfg.url, _cedar_request(req, r.context_id), deadline)
                for r in req.resource_refs
            ]
            return _cedar_result(bodies, cfg)
        body = self._post(cfg, cfg.url, req.model_dump(mode="json"), deadline)
        return PolicyProviderResult.model_validate(body)

    def run(
        self, req: PolicyProviderRequest
    ) -> tuple[list[tuple[ProviderConfig, PolicyProviderResult | None]], dict[str, CallMeta]]:
        """Call every provider concurrently. Never raises: failures are ``None`` results plus ``CallMeta``."""
        pairs: list[tuple[ProviderConfig, PolicyProviderResult | None]] = []
        call_metadata: dict[str, CallMeta] = {}
        if not self.configs:
            return pairs, call_metadata
        executor = ThreadPoolExecutor(
            max_workers=min(self._max_workers, len(self.configs)), thread_name_prefix="ales-prov"
        )
        try:
            futures: list[tuple[ProviderConfig, Future[ProviderCallResult]]] = [
                (provider, executor.submit(self._call_one, provider, req)) for provider in self.configs
            ]
            for config, future in futures:
                try:
                    result, meta = future.result(timeout=config.timeout_s + 1.0)
                except FutureTimeout:
                    result, meta = None, CallMeta(latency_ms=int(config.timeout_s * 1000), error="timeout")
                pairs.append((config, result))
                call_metadata[config.name] = meta
        finally:
            executor.shutdown(
                wait=False, cancel_futures=True
            )  # a stuck provider thread must not hold the request
        return pairs, call_metadata


class _Unavailable(Exception):
    """Internal: the provider could not give a usable answer (message is a short stable code)."""
