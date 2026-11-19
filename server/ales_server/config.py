"""Environment-driven server settings. Every malformed value is a startup error (fail closed)."""

from __future__ import annotations

import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ales_core import ProviderConfig


class ConfigError(RuntimeError):
    """The server configuration is invalid; the process must not start serving."""


_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"", "0", "false", "no", "off"}


def env_bool(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    raise ConfigError(f"{name} must be one of 1/0/true/false, got {raw!r}")


def env_number(
    env: Mapping[str, str], name: str, default: float, *, minimum: float, integer: bool = False
) -> float:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        val = int(raw) if integer else float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if not math.isfinite(val) or val < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {raw!r}")
    return val


ENFORCE_WORKLOADS_MODES = ("auto", "strict", "off")
ENVIRONMENTS = ("development", "production")
PURGE_POLICIES = ("purge", "deny-only")


@dataclass(frozen=True)
class JwksSettings:
    """Live-JWKS cache bounds (seconds), used only when ``ALES_OIDC_CONFIG`` has a ``jwks_uri``."""

    ttl: float = 300.0  # ALES_OIDC_JWKS_TTL: how long a fetched key set is trusted without refetching
    min_refresh: float = 30.0  # ALES_OIDC_JWKS_MIN_REFRESH: minimum gap between fetch attempts
    max_stale: float = (
        3600.0  # ALES_OIDC_JWKS_MAX_STALE: longest the cache is served after fetches start failing
    )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> JwksSettings:
        e = os.environ if env is None else env
        return cls(
            ttl=env_number(e, "ALES_OIDC_JWKS_TTL", 300.0, minimum=1),
            min_refresh=env_number(e, "ALES_OIDC_JWKS_MIN_REFRESH", 30.0, minimum=0),
            max_stale=env_number(e, "ALES_OIDC_JWKS_MAX_STALE", 3600.0, minimum=0),
        )


@dataclass(frozen=True)
class Settings:
    require_signatures: bool
    max_body: int
    snapshot_lease: int
    outbox_interval: float  # seconds; 0 disables the background worker
    approval_allow_self: bool = False  # ALES_APPROVAL_ALLOW_SELF: dev/single-admin escape hatch
    enforce_workloads: str = "auto"  # ALES_ENFORCE_WORKLOADS: auto | strict | off
    environment: str = "development"  # ALES_ENV: development | production
    require_grants: bool = False  # ALES_REQUIRE_GRANTS: pin the grants gate (default on in production)
    purge_policy: str = "purge"  # ALES_PURGE_POLICY: purge | deny-only (production needs targets for "purge")
    policy_providers: tuple[
        ProviderConfig, ...
    ] = ()  # ALES_POLICY_PROVIDERS: external policy providers (v0.4)
    release_ttl: int = 30  # ALES_RELEASE_TTL_SECONDS: upper bound on a release receipt's lifetime
    entitlements_required: bool = (
        True  # ALES_ENTITLEMENTS_REQUIRED: static provider failure -> UNKNOWN (vs groups=[])
    )

    @property
    def production(self) -> bool:
        return self.environment == "production"

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        require_signatures: bool | None = None,
        max_body: int | None = None,
        snapshot_lease: int | None = None,
        outbox_interval: float | None = None,
        approval_allow_self: bool | None = None,
        enforce_workloads: str | None = None,
        require_grants: bool | None = None,
    ) -> Settings:
        e = os.environ if env is None else env
        environment = (e.get("ALES_ENV") or "development").strip().lower()
        if environment not in ENVIRONMENTS:
            raise ConfigError(f"ALES_ENV must be one of {ENVIRONMENTS}, got {environment!r}")
        # production hardens the default: workload identity is enforced for every agent unless set explicitly
        default_mode = "strict" if environment == "production" else "auto"
        mode = (
            enforce_workloads
            if enforce_workloads is not None
            else (e.get("ALES_ENFORCE_WORKLOADS") or default_mode)
        )
        mode = mode.strip().lower()
        if mode not in ENFORCE_WORKLOADS_MODES:
            raise ConfigError(
                f"ALES_ENFORCE_WORKLOADS must be one of {ENFORCE_WORKLOADS_MODES}, got {mode!r}"
            )
        policy = (e.get("ALES_PURGE_POLICY") or "purge").strip().lower()
        if policy not in PURGE_POLICIES:
            raise ConfigError(f"ALES_PURGE_POLICY must be one of {PURGE_POLICIES}, got {policy!r}")
        from .providers import parse_providers  # local: providers imports ConfigError from this module

        return cls(
            policy_providers=parse_providers(
                e.get("ALES_POLICY_PROVIDERS"), production=environment == "production", env=e
            ),
            release_ttl=int(env_number(e, "ALES_RELEASE_TTL_SECONDS", 30, minimum=1, integer=True)),
            purge_policy=policy,
            entitlements_required=env_bool(e, "ALES_ENTITLEMENTS_REQUIRED", default=True),
            approval_allow_self=(
                env_bool(e, "ALES_APPROVAL_ALLOW_SELF")
                if approval_allow_self is None
                else bool(approval_allow_self)
            ),
            enforce_workloads=mode,
            environment=environment,
            require_grants=(
                env_bool(e, "ALES_REQUIRE_GRANTS", default=environment == "production")
                if require_grants is None
                else bool(require_grants)
            ),
            require_signatures=(
                env_bool(e, "ALES_REQUIRE_SIGNATURES")
                if require_signatures is None
                else bool(require_signatures)
            ),
            max_body=int(env_number(e, "ALES_MAX_BODY", 1_048_576, minimum=1, integer=True))
            if max_body is None
            else int(max_body),
            snapshot_lease=int(env_number(e, "ALES_SNAPSHOT_LEASE", 60, minimum=1, integer=True))
            if snapshot_lease is None
            else int(snapshot_lease),
            outbox_interval=env_number(e, "ALES_OUTBOX_INTERVAL", 5.0, minimum=0)
            if outbox_interval is None
            else float(outbox_interval),
        )
