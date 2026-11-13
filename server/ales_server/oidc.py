"""Optional OIDC / JWT bearer authentication (SPEC v0.3 "Enterprise identity").

Enabled by ``ALES_OIDC_CONFIG`` (a JSON object)::

    {"issuer": "https://idp.example.com/",
     "audience": "ales-invariant",
     "jwks": {"keys": [ ...static JWKS... ]}   # or "jwks_file": "/path/to/jwks.json"
                                               # or "jwks_uri": "https://idp.example.com/.well-known/jwks.json"
     "claim_mapping": {"tenant_id": "org_id", "subject": "sub", "roles": "ales_roles"}}
     # "roles" may instead be {"static": ["read"]} to give every token from this issuer fixed roles.

Key sources
-----------
Exactly one of ``jwks`` (inline), ``jwks_file`` (read once at startup) or ``jwks_uri``.

* ``jwks_uri``: fetched with httpx (5 s timeout, TLS verification on, no redirects, 1 MiB cap). ``https``
  only; plain ``http`` is accepted solely for ``127.0.0.1`` / ``localhost`` (tests, sidecars). The key set
  is cached for ``ALES_OIDC_JWKS_TTL`` s (default 300). A token whose ``kid`` is not in the cache triggers
  one refetch, at most once per ``ALES_OIDC_JWKS_MIN_REFRESH`` s (default 30), so rotation works without a
  restart and a flood of garbage ``kid`` values cannot stampede the IdP. All fetches are serialised
  under one lock (thread-safe; a cache miss blocks other verifications for up to the fetch timeout).
* Fail closed: a failed fetch with no cached keys rejects every token (401); with a cache it keeps
  serving the cached keys (logged) but never longer than ``ALES_OIDC_JWKS_MAX_STALE`` s (default 3600)
  after the failure streak began, after which every token is rejected until a fetch succeeds. Failures are
  logged once when a streak starts and once when the stale bound is crossed, not per request.
* Per-token revocation: ``ALES_DENYLIST_FILE`` ``jwt_jtis`` rejects individual tokens by their ``jti`` claim
  (see ``denylist.py``). ``jti`` is optional per RFC 7519; set ``"require_jti": true`` in this config to
  reject (401) tokens that carry none, which closes the "unlisted because it has no jti" gap. Without a
  denylist entry a token stays valid until ``exp`` (see residual risk R13).

* Algorithms: ``RS256`` (RSA keys >= 2048 bits) and ``ES256`` (P-256 keys) only. ``none``, ``HS*`` and
  anything else are rejected; a key is bound to its algorithm family so an RSA key can never verify ES256
  or vice versa (no algorithm confusion). ``crit`` headers are rejected.
* ``iss`` must equal the configured issuer exactly; ``aud`` (string or list) must contain the configured
  audience exactly; ``exp`` is required; ``exp``/``nbf`` are checked with 60 s of clock skew.
* Identity comes ONLY from ``claim_mapping``: a missing or ill-typed mapped claim is a 401. Roles must be a
  non-empty subset of the known roles and the tenant may not end in ``:verify``.
* Routing (see ``auth.Authenticator``): when OIDC is configured, a bearer token that is shaped like a JWT
  is verified here and **never** looked up in the static token registry; every failure is a 401.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .config import ConfigError, JwksSettings

log = logging.getLogger("ales.server.oidc")

ALLOWED_ALGS = frozenset({"RS256", "ES256"})
SKEW_SECONDS = 60
MIN_RSA_BITS = 2048
_JWT_SHAPE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_PubKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost"})
FETCH_TIMEOUT = 5.0
MAX_JWKS_BYTES = 1_048_576


class OidcError(Exception):
    """Token rejected. The message is for logs only; callers answer a uniform 401."""


def looks_like_jwt(token: str) -> bool:
    return bool(_JWT_SHAPE.match(token))


def _b64u(segment: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", segment):
        raise OidcError("bad base64url")
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError) as exc:
        raise OidcError("bad base64url") from exc


def _json_obj(raw: bytes, what: str) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise OidcError(f"{what} is not JSON") from exc
    if not isinstance(data, dict):
        raise OidcError(f"{what} is not an object")
    return data


def _int_from_b64u(value: object, what: str) -> int:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"JWK {what} must be a non-empty base64url string")
    try:
        return int.from_bytes(_b64u(value), "big")
    except OidcError as exc:
        raise ConfigError(f"JWK {what} is not valid base64url") from exc


def _load_jwk(jwk: Mapping[str, Any]) -> tuple[str | None, _PubKey, str] | None:
    """``(kid, public_key, alg_family)`` or None when the key is not usable for signature verification."""
    kty = jwk.get("kty")
    if jwk.get("use") not in (None, "sig"):
        return None
    kid = jwk.get("kid")
    if kid is not None and not isinstance(kid, str):
        raise ConfigError("JWK kid must be a string")
    if kty == "RSA":
        n, e = _int_from_b64u(jwk.get("n"), "n"), _int_from_b64u(jwk.get("e"), "e")
        try:
            rsa_key = rsa.RSAPublicNumbers(e, n).public_key()
        except ValueError as exc:
            raise ConfigError(f"invalid RSA JWK: {exc}") from exc
        if rsa_key.key_size < MIN_RSA_BITS:
            raise ConfigError(f"RSA JWK must be at least {MIN_RSA_BITS} bits")
        alg = "RS256"
        key: _PubKey = rsa_key
    elif kty == "EC":
        if jwk.get("crv") != "P-256":
            return None  # only ES256 is supported
        x, y = _int_from_b64u(jwk.get("x"), "x"), _int_from_b64u(jwk.get("y"), "y")
        try:
            key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        except ValueError as exc:
            raise ConfigError(f"invalid EC JWK: {exc}") from exc
        alg = "ES256"
    else:
        return None
    if jwk.get("alg") not in (None, alg):
        raise ConfigError(f"JWK alg {jwk.get('alg')!r} does not match its key type ({alg})")
    return kid, key, alg


@dataclass(frozen=True)
class _KeySet:
    by_kid: dict[str, tuple[_PubKey, str]]
    sole: tuple[_PubKey, str] | None


def _build_keyset(keys: list[tuple[str | None, _PubKey, str]]) -> _KeySet:
    if not keys:
        raise ConfigError("OIDC JWKS contains no usable RS256/ES256 signature key")
    kids = [k for k, _, _ in keys if k is not None]
    if len(kids) != len(set(kids)):
        raise ConfigError("OIDC JWKS contains duplicate kid values")
    if any(k is None for k, _, _ in keys) and len(keys) > 1:
        raise ConfigError("OIDC JWKS with several keys requires a kid on every key")
    return _KeySet({k: (key, alg) for k, key, alg in keys if k is not None}, keys[0][1:] if len(keys) == 1 else None)


def _parse_jwks(jwks: object) -> _KeySet:
    """Validate a JWKS document and build its key set (same constraints for static and fetched keys)."""
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise ConfigError('OIDC JWKS must be an object like {"keys": [...]}')
    keys: list[tuple[str | None, _PubKey, str]] = []
    for jwk in jwks["keys"]:
        if not isinstance(jwk, dict):
            raise ConfigError("OIDC JWKS keys must be objects")
        loaded = _load_jwk(jwk)
        if loaded is not None:
            keys.append(loaded)
    return _build_keyset(keys)


def validate_jwks_uri(uri: object) -> str:
    if not isinstance(uri, str) or not uri:
        raise ConfigError("OIDC jwks_uri must be a non-empty string")
    parts = urlsplit(uri)
    host = (parts.hostname or "").lower()
    if not host or parts.username or parts.password:
        raise ConfigError("OIDC jwks_uri must be an absolute URL without credentials")
    if parts.scheme == "https":
        return uri
    if parts.scheme == "http" and host in _LOOPBACK_HOSTS:
        return uri
    raise ConfigError("OIDC jwks_uri must use https (http is accepted only for 127.0.0.1 and localhost)")


class RemoteJwks:
    """TTL-cached, rotation-aware, fail-closed JWKS fetcher (see the module docstring)."""

    def __init__(
        self,
        uri: str,
        settings: JwksSettings | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        timeout: float = FETCH_TIMEOUT,
    ) -> None:
        self.uri = validate_jwks_uri(uri)
        self.settings = settings or JwksSettings()
        self._clock, self._timeout = clock, timeout
        self._lock = threading.Lock()
        self._ks: _KeySet | None = None
        self._fetched_at = 0.0
        self._last_attempt: float | None = None
        self._fail_since: float | None = None
        self._stale_logged = False

    def _fetch(self) -> _KeySet:
        with httpx.Client(timeout=self._timeout, follow_redirects=False) as client, client.stream(
            "GET", self.uri, headers={"Accept": "application/json"}
        ) as resp:
            if resp.status_code != 200:
                raise OidcError(f"jwks fetch returned HTTP {resp.status_code}")
            body = bytearray()
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) > MAX_JWKS_BYTES:
                    raise OidcError("jwks response too large")
        try:
            doc = json.loads(bytes(body))
        except ValueError as exc:
            raise OidcError("jwks response is not JSON") from exc
        return _parse_jwks(doc)

    def _refresh(self, now: float) -> None:
        self._last_attempt = now
        try:
            ks = self._fetch()
        except (httpx.HTTPError, OidcError, ConfigError, OSError) as exc:
            if self._fail_since is None:
                self._fail_since = now
                log.warning("JWKS fetch failed (%s); %s", exc, "serving cached keys" if self._ks else "no cached keys")
            return
        self._ks, self._fetched_at, self._fail_since, self._stale_logged = ks, now, None, False

    def _may_attempt(self, now: float) -> bool:
        return self._last_attempt is None or now - self._last_attempt >= self.settings.min_refresh

    def keyset(self, kid: str | None) -> _KeySet:
        """The key set to verify a token whose header ``kid`` is given, or :class:`OidcError` (fail closed)."""
        with self._lock:
            now = self._clock()
            if self._ks is None:
                if self._may_attempt(now):
                    self._refresh(now)
                if self._ks is None:
                    raise OidcError("JWKS unavailable")
                return self._ks
            expired = now - self._fetched_at >= self.settings.ttl
            if (expired or (kid is not None and kid not in self._ks.by_kid)) and self._may_attempt(now):
                self._refresh(now)
            if self._fail_since is not None and now - self._fail_since > self.settings.max_stale:
                if not self._stale_logged:
                    self._stale_logged = True
                    log.error("JWKS cache is older than ALES_OIDC_JWKS_MAX_STALE; rejecting all OIDC tokens")
                raise OidcError("JWKS stale beyond the allowed bound")
            return self._ks


class OidcVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        tenant_claim: str,
        subject_claim: str,
        roles_claim: str | None,
        static_roles: list[str] | None,
        known_roles: frozenset[str],
        keyset: _KeySet | None = None,
        remote: RemoteJwks | None = None,
        clock: Callable[[], float] = time.time,
        require_jti: bool = False,
    ) -> None:
        if (keyset is None) == (remote is None):
            raise ConfigError("OidcVerifier needs exactly one of a static key set or a remote JWKS")
        self._static = keyset
        self.remote = remote
        self.issuer, self.audience = issuer, audience
        self._tenant_claim, self._subject_claim = tenant_claim, subject_claim
        self._roles_claim, self._static_roles = roles_claim, static_roles
        self._known_roles = known_roles
        self._clock = clock
        self.require_jti = require_jti

    # ---------------------------------------------------------------- construction
    @classmethod
    def from_config(
        cls,
        raw: str,
        known_roles: frozenset[str],
        *,
        clock: Callable[[], float] = time.time,
        jwks_settings: JwksSettings | None = None,
        jwks_clock: Callable[[], float] = time.monotonic,
    ) -> OidcVerifier:
        try:
            cfg = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"ALES_OIDC_CONFIG is not valid JSON: {exc.msg}") from exc
        if not isinstance(cfg, dict):
            raise ConfigError("ALES_OIDC_CONFIG must be a JSON object")
        issuer, audience = cfg.get("issuer"), cfg.get("audience")
        if not isinstance(issuer, str) or not issuer or not isinstance(audience, str) or not audience:
            raise ConfigError("ALES_OIDC_CONFIG needs non-empty string issuer and audience")
        sources = [k for k in ("jwks", "jwks_file", "jwks_uri") if k in cfg]
        if len(sources) != 1:
            raise ConfigError("ALES_OIDC_CONFIG needs exactly one of jwks, jwks_file or jwks_uri")
        keyset: _KeySet | None = None
        remote: RemoteJwks | None = None
        if sources[0] == "jwks_uri":
            remote = RemoteJwks(cfg["jwks_uri"], jwks_settings, clock=jwks_clock)
        else:
            if sources[0] == "jwks":
                jwks = cfg["jwks"]
            else:
                path = cfg["jwks_file"]
                try:
                    jwks = json.loads(Path(str(path)).read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    raise ConfigError(f"cannot load OIDC jwks_file {path!r}: {exc}") from exc
            keyset = _parse_jwks(jwks)

        require_jti = cfg.get("require_jti", False)
        if not isinstance(require_jti, bool):
            raise ConfigError("ALES_OIDC_CONFIG require_jti must be a boolean")
        cm = cfg.get("claim_mapping")
        if not isinstance(cm, dict):
            raise ConfigError("ALES_OIDC_CONFIG needs a claim_mapping object")
        tenant_claim, subject_claim, roles = cm.get("tenant_id"), cm.get("subject"), cm.get("roles")
        if not isinstance(tenant_claim, str) or not tenant_claim or not isinstance(subject_claim, str) or not subject_claim:
            raise ConfigError("claim_mapping needs string tenant_id and subject claim names")
        roles_claim: str | None = None
        static_roles: list[str] | None = None
        if isinstance(roles, str) and roles:
            roles_claim = roles
        elif isinstance(roles, dict) and set(roles) == {"static"}:
            sr = roles["static"]
            if not isinstance(sr, list) or not sr or not all(isinstance(r, str) for r in sr):
                raise ConfigError("claim_mapping.roles.static must be a non-empty list of role names")
            unknown = set(sr) - known_roles
            if unknown:
                raise ConfigError(f"unknown static role(s) {sorted(unknown)}; valid: {sorted(known_roles)}")
            static_roles = sorted(set(sr))
        else:
            raise ConfigError('claim_mapping.roles must be a claim name or {"static": [...]}')
        return cls(
            issuer=issuer,
            audience=audience,
            keyset=keyset,
            remote=remote,
            tenant_claim=tenant_claim,
            subject_claim=subject_claim,
            roles_claim=roles_claim,
            static_roles=static_roles,
            known_roles=known_roles,
            clock=clock,
            require_jti=require_jti,
        )

    # ---------------------------------------------------------------- verification
    def verify(self, token: str) -> tuple[str, str, frozenset[str]]:
        """Return ``(subject, tenant_id, roles)`` or raise :class:`OidcError`."""
        subject, tenant, roles, _jti = self.verify_claims(token)
        return subject, tenant, roles

    def verify_claims(self, token: str) -> tuple[str, str, frozenset[str], str | None]:
        """Like :meth:`verify` plus the token's ``jti`` (None when absent), for per-token revocation."""
        parts = token.split(".")
        if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
            raise OidcError("not a signed compact JWT")
        header = _json_obj(_b64u(parts[0]), "header")
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in ALLOWED_ALGS:
            raise OidcError(f"algorithm {alg!r} not allowed")
        if "crit" in header:
            raise OidcError("crit header not supported")
        self._verify_signature(header, alg, f"{parts[0]}.{parts[1]}".encode("ascii"), _b64u(parts[2]))
        claims = _json_obj(_b64u(parts[1]), "payload")
        self._check_registered(claims)
        jti = claims.get("jti")
        if jti is not None and (not isinstance(jti, str) or not jti):
            raise OidcError("jti claim must be a non-empty string")
        if jti is None and self.require_jti:
            raise OidcError("jti claim required (require_jti)")
        subject, tenant, roles = self._map(claims)
        return subject, tenant, roles, jti

    def _verify_signature(self, header: dict[str, Any], alg: str, signing_input: bytes, sig: bytes) -> None:
        kid = header.get("kid")
        if kid is not None and not isinstance(kid, str):
            raise OidcError("unknown kid")
        if self._static is not None:
            ks = self._static
        else:
            assert self.remote is not None
            ks = self.remote.keyset(kid)
        if kid is not None:
            if kid not in ks.by_kid:
                raise OidcError("unknown kid")
            key, family = ks.by_kid[kid]
        elif ks.sole is not None:
            key, family = ks.sole
        else:
            raise OidcError("kid required")
        if family != alg:
            raise OidcError("key does not match the token algorithm")
        try:
            if isinstance(key, rsa.RSAPublicKey):
                key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
            else:
                if len(sig) != 64:
                    raise OidcError("bad ES256 signature length")
                r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
                key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise OidcError("signature verification failed") from exc

    def _check_registered(self, claims: dict[str, Any]) -> None:
        if claims.get("iss") != self.issuer:
            raise OidcError("issuer mismatch")
        aud = claims.get("aud")
        if isinstance(aud, str):
            ok = aud == self.audience
        elif isinstance(aud, list):
            ok = any(isinstance(a, str) and a == self.audience for a in aud)
        else:
            ok = False
        if not ok:
            raise OidcError("audience mismatch")
        now = self._clock()
        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, int | float):
            raise OidcError("exp required")
        if now - SKEW_SECONDS >= exp:
            raise OidcError("token expired")
        if "nbf" in claims:
            nbf = claims["nbf"]
            if isinstance(nbf, bool) or not isinstance(nbf, int | float):
                raise OidcError("bad nbf")
            if now + SKEW_SECONDS < nbf:
                raise OidcError("token not yet valid")

    def _map(self, claims: dict[str, Any]) -> tuple[str, str, frozenset[str]]:
        tenant = claims.get(self._tenant_claim)
        subject = claims.get(self._subject_claim)
        if not isinstance(tenant, str) or not tenant or tenant != tenant.strip():
            raise OidcError("tenant claim missing or invalid")
        if tenant.endswith(":verify"):
            raise OidcError("reserved tenant suffix")
        if not isinstance(subject, str) or not subject:
            raise OidcError("subject claim missing or invalid")
        if self._static_roles is not None:
            roles = list(self._static_roles)
        else:
            assert self._roles_claim is not None
            raw = claims.get(self._roles_claim)
            if not isinstance(raw, list) or not raw or not all(isinstance(r, str) for r in raw):
                raise OidcError("roles claim missing or invalid")
            roles = list(raw)
        if not set(roles) <= self._known_roles:
            raise OidcError("roles claim contains unknown roles")
        return subject, tenant, frozenset(roles)
