"""Bearer-token authentication, tenant binding and role enforcement (SPEC v0.2).

Design
------
* Tokens live in a registry keyed by ``sha256(token)``; plaintext tokens are never retained after
  load. Lookup recomputes the digest of the presented token and compares it against *every*
  stored digest with :func:`hmac.compare_digest` (no early exit), so timing does not reveal which
  or whether a token matched.
* Authentication is an HTTP middleware, so it is fail-closed by construction: a route added
  later is authenticated unless its path is explicitly listed in :data:`EXEMPT_PATHS`. Role checks
  are per-route dependencies (:func:`require`).
* The effective tenant is **always** the token's tenant. Any tenant claimed in the
  ``X-Tenant-Id`` header, the ``tenant_id`` query parameter (checked here, for every route) or the
  request body (checked by :func:`bind_tenant`) that disagrees yields
  ``403 {"detail": "tenant mismatch with credential"}``.
* Dev fallback: with no token source configured and ``ALES_DEV_ALLOW_ANONYMOUS=1`` the caller is
  anonymous (all roles) and the tenant comes from ``X-Tenant-Id``. With no token source and no
  dev flag, protected routes answer 503: a misconfigured server never serves unauthenticated.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from .config import ConfigError, JwksSettings, env_bool
from .denylist import RELOAD_INTERVAL, Denylist, FileWatch
from .oidc import OidcError, OidcVerifier, looks_like_jwt

log = logging.getLogger("ales.server.auth")

ROLES = frozenset({"ingest", "revoke", "read", "admin"})
EXEMPT_PATHS = frozenset({"/v1/healthz", "/v1/readyz"})
TENANT_MISMATCH = "tenant mismatch with credential"
#: Suffix of the scratch namespace used by POST /v1/verify; real tenants may not live in it.
VERIFY_SUFFIX = ":verify"


@dataclass(frozen=True)
class Identity:
    """An authenticated caller. ``tenant_id`` is None only for an anonymous caller with no header."""

    subject: str
    tenant_id: str | None
    roles: frozenset[str]
    anonymous: bool = False
    # OIDC callers only (v0.5): the verified token's issuer, its mapped groups (None = no groups mapping
    # configured), whether the groups claim could not be resolved (Entra overage) and the token's ``exp``.
    issuer: str | None = None
    groups: tuple[str, ...] | None = None
    groups_unresolved: bool = False
    token_exp: float | None = None


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


class TokenRegistry:
    """``sha256(token) -> Identity`` with constant-time lookup."""

    def __init__(self, records: Mapping[str, Mapping[str, Any]]):
        self._entries: list[tuple[bytes, Identity]] = []
        seen: set[bytes] = set()
        for token, record in records.items():
            if (
                not isinstance(token, str)
                or not token
                or token != token.strip()
                or any(ord(c) < 33 or ord(c) == 127 for c in token)
            ):
                raise ConfigError("token must be a non-empty string without whitespace or control characters")
            if not isinstance(record, Mapping):
                raise ConfigError("token record must be an object")
            tenant = record.get("tenant_id")
            if not isinstance(tenant, str) or not tenant:
                raise ConfigError("token record needs a non-empty string tenant_id")
            if tenant.endswith(VERIFY_SUFFIX):
                raise ConfigError(f"tenant_id may not end with the reserved suffix {VERIFY_SUFFIX!r}")
            roles = record.get("roles")
            if not isinstance(roles, list | tuple) or not roles or not all(isinstance(r, str) for r in roles):
                raise ConfigError("token record needs a non-empty list of roles")
            unknown = set(roles) - ROLES
            if unknown:
                raise ConfigError(f"unknown role(s) {sorted(unknown)}; valid: {sorted(ROLES)}")
            subject = record.get("subject")
            if not isinstance(subject, str) or not subject:
                raise ConfigError("token record needs a non-empty string subject")
            d = _digest(token)
            if d in seen:
                raise ConfigError("duplicate token in registry")
            seen.add(d)
            self._entries.append((d, Identity(subject=subject, tenant_id=tenant, roles=frozenset(roles))))

    def __len__(self) -> int:
        return len(self._entries)

    def lookup(self, token: str) -> Identity | None:
        presented = _digest(token)
        found: Identity | None = None
        for stored, ident in self._entries:  # no early exit: constant work per attempt
            if hmac.compare_digest(stored, presented):
                found = ident
        return found

    @classmethod
    def from_sources(
        cls, env: Mapping[str, str] | None = None, explicit: Mapping[str, Mapping[str, Any]] | None = None
    ) -> TokenRegistry | None:
        """Load ``explicit`` (tests) or ``ALES_TOKENS`` + ``ALES_TOKENS_FILE``. None if nothing is configured."""
        if explicit is not None:
            return cls(explicit) if explicit else None
        merged = collect_tokens(os.environ if env is None else env)
        return cls(merged) if merged else None


def collect_tokens(e: Mapping[str, str]) -> dict[str, Any]:
    """Merge ``ALES_TOKENS`` and ``ALES_TOKENS_FILE`` into one ``token -> record`` map (re-read from disk)."""
    merged: dict[str, Any] = {}
    raw = e.get("ALES_TOKENS")
    if raw and raw.strip():
        merged.update(_parse_json("ALES_TOKENS", raw))
    path = e.get("ALES_TOKENS_FILE")
    if path and path.strip():
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read ALES_TOKENS_FILE {path!r}: {exc}") from exc
        from_file = _parse_json("ALES_TOKENS_FILE", text)
        dup = set(merged) & set(from_file)
        if dup:
            raise ConfigError("the same token appears in both ALES_TOKENS and ALES_TOKENS_FILE")
        merged.update(from_file)
    return merged


class TokenReloader:
    """Hot reload of ``ALES_TOKENS_FILE``: stat at most every 5 s, re-read only on change.

    A reload that fails to parse or validate is logged and the previous registry stays in force. An
    empty-but-valid file is applied (it revokes every static token), because that is a legitimate
    emergency action.
    """

    def __init__(self, env: Mapping[str, str], path: str, *, interval: float = RELOAD_INTERVAL):
        self._env = dict(env)
        self.watch = FileWatch(path, interval=interval)

    def poll(self) -> tuple[str, TokenRegistry | None]:
        """``("none", None)`` when unchanged, ``("ok", registry)`` or ``("error", None)`` after a reload attempt."""
        if not self.watch.changed():
            return "none", None
        try:
            return "ok", TokenRegistry(collect_tokens(self._env))
        except ConfigError as exc:
            log.error("token reload failed, keeping the previous registry: %s", exc)
            return "error", None


def _parse_json(source: str, text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{source} is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{source} must be a JSON object mapping token -> record")
    return data


def parse_bearer(header: str | None) -> str | None:
    """Strictly parse ``Authorization: Bearer <token>``; anything else is None."""
    if not header:
        return None
    parts = header.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return None
    tok = parts[1]
    if any(ord(c) < 33 or ord(c) == 127 for c in tok):
        return None
    return tok


class Authenticator:
    def __init__(
        self,
        registry: TokenRegistry | None,
        allow_anonymous: bool,
        oidc: OidcVerifier | None = None,
        *,
        denylist: Denylist | None = None,
        reloader: TokenReloader | None = None,
    ):
        self.registry = registry
        self.oidc = oidc
        self.denylist = denylist
        self.reloader = reloader
        self.metrics: Any = None  # set by create_app; process-wide counters only (no tenant labels)
        self._reload_lock = threading.Lock()
        self.allow_anonymous = bool(allow_anonymous) and registry is None and oidc is None
        if (registry is not None or oidc is not None) and allow_anonymous:
            log.warning("ALES_DEV_ALLOW_ANONYMOUS is ignored because tokens are configured")
        if self.allow_anonymous:
            log.warning(
                "*** ALES DEV MODE: ANONYMOUS ACCESS ENABLED (ALES_DEV_ALLOW_ANONYMOUS=1, no tokens configured). "
                "Every caller has ALL roles and chooses its own tenant. NEVER USE THIS IN PRODUCTION. ***"
            )
        elif registry is None and oidc is None:
            log.error(
                "no tokens configured (ALES_TOKENS / ALES_TOKENS_FILE): protected routes will answer 503 "
                "until credentials are configured"
            )

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        tokens: Mapping[str, Mapping[str, Any]] | None = None,
        allow_anonymous: bool | None = None,
        oidc: OidcVerifier | None = None,
    ) -> Authenticator:
        e = os.environ if env is None else env
        registry = TokenRegistry.from_sources(e, tokens)
        path = (e.get("ALES_TOKENS_FILE") or "").strip()
        reloader = TokenReloader(e, path) if (tokens is None and path) else None
        deny_path = (e.get("ALES_DENYLIST_FILE") or "").strip()
        denylist = Denylist(deny_path) if deny_path else None
        anon = env_bool(e, "ALES_DEV_ALLOW_ANONYMOUS") if allow_anonymous is None else allow_anonymous
        # ALES_DEV_ALLOW_ANONYMOUS must be exactly "1" per the contract; "true" etc. are accepted too.
        if oidc is None:
            raw = e.get("ALES_OIDC_CONFIG")
            if raw and raw.strip():
                oidc = OidcVerifier.from_config(raw, ROLES, jwks_settings=JwksSettings.from_env(e))
        auth = cls(registry, anon, oidc, denylist=denylist, reloader=reloader)
        return auth

    def _inc(self, name: str, label: str = "") -> None:
        if self.metrics is not None:
            self.metrics.inc(name, None, label)

    def _refresh(self) -> None:
        if self.denylist is not None:
            self.denylist.refresh()
        if self.reloader is None:
            return
        with self._reload_lock:
            outcome, registry = self.reloader.poll()
            if outcome == "ok" and registry is not None:
                self.registry = registry  # atomic swap; in-flight lookups finish on the old one
                log.warning("token registry reloaded from ALES_TOKENS_FILE: %d token(s)", len(registry))
            if outcome != "none":
                self._inc("token_reload", outcome)

    def _denied(self, subject: str, *, jwt: bool) -> bool:
        if self.denylist is not None and self.denylist.denies(subject, jwt=jwt):
            log.warning("rejected denylisted identity (subject=%r, oidc=%s)", subject[:128], jwt)
            self._inc("denylist_rejection", "oidc" if jwt else "static")
            return True
        return False

    def authenticate(self, request: Request) -> Identity | JSONResponse:
        """Return the caller's Identity or the error response to send."""
        self._refresh()
        token = parse_bearer(request.headers.get("authorization"))
        if self.oidc is not None and token is not None and looks_like_jwt(token):
            # A JWT-shaped token is verified as a JWT and NEVER falls through to the static registry.
            try:
                vt = self.oidc.verify_token(token)
                subject, jwt_tenant, roles, jti = vt.subject, vt.tenant, vt.roles, vt.jti
            except OidcError as exc:
                log.info("rejected JWT: %s", exc)
                return _unauthorized()
            if self._denied(subject, jwt=True):
                return _unauthorized()
            if self.denylist is not None and self.denylist.denies_jti(jti):
                log.warning("rejected denylisted JWT (jti=%r)", (jti or "")[:128])
                self._inc("denylist_rejection", "jti")
                return _unauthorized()
            return Identity(
                subject=subject,
                tenant_id=jwt_tenant,
                roles=roles,
                issuer=vt.issuer,
                groups=vt.groups,
                groups_unresolved=vt.groups_unresolved,
                token_exp=vt.exp,
            )

        if self.registry is None and self.oidc is None:
            if not self.allow_anonymous:
                return JSONResponse(
                    status_code=503, content={"detail": "authentication is not configured on this server"}
                )
            headers = request.headers.getlist("x-tenant-id")
            if len(set(headers)) > 1:
                return _tenant_mismatch()
            tenant = headers[0] if headers and headers[0] else None
            if tenant is not None and tenant.endswith(VERIFY_SUFFIX):
                return _tenant_mismatch()
            return Identity("anonymous", tenant, ROLES, anonymous=True)

        ident = self.registry.lookup(token) if (self.registry is not None and token is not None) else None
        if ident is None or self._denied(ident.subject, jwt=False):
            return _unauthorized()
        return ident


def _unauthorized() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"detail": "missing or invalid credentials"},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _tenant_mismatch() -> JSONResponse:
    return JSONResponse(status_code=403, content={"detail": TENANT_MISMATCH})


def make_auth_middleware(
    auth: Authenticator, extra_exempt: frozenset[str] = frozenset()
) -> Callable[[Request, RequestResponseEndpoint], Any]:
    exempt = EXEMPT_PATHS | extra_exempt

    async def auth_middleware(request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in exempt:
            return await call_next(request)
        if auth.oidc is not None and auth.oidc.remote is not None:
            result = await run_in_threadpool(auth.authenticate, request)  # a JWKS fetch may block
        else:
            result = auth.authenticate(request)
        if isinstance(result, JSONResponse):
            return result
        # Tenant claims carried outside the body must agree with the credential on EVERY route.
        if result.tenant_id is not None:
            claimed = request.headers.getlist("x-tenant-id") + request.query_params.getlist("tenant_id")
            if any(c != result.tenant_id for c in claimed):
                return _tenant_mismatch()
        request.state.identity = result
        return await call_next(request)

    return auth_middleware


def identity_of(request: Request) -> Identity:
    ident = getattr(request.state, "identity", None)
    if not isinstance(ident, Identity):  # middleware did not run: never fall open
        raise HTTPException(401, detail="missing or invalid credentials")
    return ident


def require(role: str) -> Callable[[Request], Identity]:
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}")

    def dependency(request: Request) -> Identity:
        ident = identity_of(request)
        if role not in ident.roles:
            raise HTTPException(403, detail=f"role '{role}' required")
        return ident

    return dependency


def bind_tenant(ident: Identity, claimed: object | None = None) -> str:
    """Return the effective tenant: the credential's. A disagreeing claim is a 403."""
    if ident.tenant_id is not None:
        if claimed is not None and claimed != ident.tenant_id:
            raise HTTPException(403, detail=TENANT_MISMATCH)
        return ident.tenant_id
    # anonymous dev caller that sent no X-Tenant-Id: the body/query is the only source
    if not isinstance(claimed, str) or not claimed or claimed.endswith(VERIFY_SUFFIX):
        raise HTTPException(422, detail="tenant_id required (X-Tenant-Id header or request field)")
    return claimed
