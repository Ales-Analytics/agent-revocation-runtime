"""Optional OIDC / JWT bearer authentication (SPEC v0.3 "Enterprise identity").

Enabled by ``ALES_OIDC_CONFIG`` (a JSON object)::

    {"issuer": "https://idp.example.com/",
     "audience": "ales-invariant",
     "jwks": {"keys": [ ...static JWKS... ]}            # or "jwks_file": "/path/to/jwks.json"
     "claim_mapping": {"tenant_id": "org_id", "subject": "sub", "roles": "ales_roles"}}
     # "roles" may instead be {"static": ["read"]} to give every token from this issuer fixed roles.

Scope of this iteration
-----------------------
* **Static JWKS only.** Keys are loaded once at startup from the config (or ``jwks_file``). There is no
  network fetch and no key rotation without a restart. Fetching a live ``jwks_uri`` (with cache, rotation
  and kid-miss refresh) is a documented follow-up.
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
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .config import ConfigError

log = logging.getLogger("ales.server.oidc")

ALLOWED_ALGS = frozenset({"RS256", "ES256"})
SKEW_SECONDS = 60
MIN_RSA_BITS = 2048
_JWT_SHAPE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_PubKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey


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


class OidcVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        keys: list[tuple[str | None, _PubKey, str]],
        tenant_claim: str,
        subject_claim: str,
        roles_claim: str | None,
        static_roles: list[str] | None,
        known_roles: frozenset[str],
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not keys:
            raise ConfigError("OIDC JWKS contains no usable RS256/ES256 signature key")
        kids = [k for k, _, _ in keys if k is not None]
        if len(kids) != len(set(kids)):
            raise ConfigError("OIDC JWKS contains duplicate kid values")
        if any(k is None for k, _, _ in keys) and len(keys) > 1:
            raise ConfigError("OIDC JWKS with several keys requires a kid on every key")
        self.issuer, self.audience = issuer, audience
        self._by_kid = {k: (key, alg) for k, key, alg in keys if k is not None}
        self._sole = keys[0][1:] if len(keys) == 1 else None
        self._tenant_claim, self._subject_claim = tenant_claim, subject_claim
        self._roles_claim, self._static_roles = roles_claim, static_roles
        self._known_roles = known_roles
        self._clock = clock

    # ---------------------------------------------------------------- construction
    @classmethod
    def from_config(
        cls, raw: str, known_roles: frozenset[str], *, clock: Callable[[], float] = time.time
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
        if ("jwks" in cfg) == ("jwks_file" in cfg):
            raise ConfigError("ALES_OIDC_CONFIG needs exactly one of jwks or jwks_file")
        if "jwks" in cfg:
            jwks = cfg["jwks"]
        else:
            path = cfg["jwks_file"]
            try:
                jwks = json.loads(Path(str(path)).read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ConfigError(f"cannot load OIDC jwks_file {path!r}: {exc}") from exc
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise ConfigError('OIDC JWKS must be an object like {"keys": [...]}')
        keys = []
        for jwk in jwks["keys"]:
            if not isinstance(jwk, dict):
                raise ConfigError("OIDC JWKS keys must be objects")
            loaded = _load_jwk(jwk)
            if loaded is not None:
                keys.append(loaded)

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
            keys=keys,
            tenant_claim=tenant_claim,
            subject_claim=subject_claim,
            roles_claim=roles_claim,
            static_roles=static_roles,
            known_roles=known_roles,
            clock=clock,
        )

    # ---------------------------------------------------------------- verification
    def verify(self, token: str) -> tuple[str, str, frozenset[str]]:
        """Return ``(subject, tenant_id, roles)`` or raise :class:`OidcError`."""
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
        return self._map(claims)

    def _verify_signature(self, header: dict[str, Any], alg: str, signing_input: bytes, sig: bytes) -> None:
        kid = header.get("kid")
        if kid is not None:
            if not isinstance(kid, str) or kid not in self._by_kid:
                raise OidcError("unknown kid")
            key, family = self._by_kid[kid]
        elif self._sole is not None:
            key, family = self._sole
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
