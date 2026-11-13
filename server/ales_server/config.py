"""Environment-driven server settings. Every malformed value is a startup error (fail closed)."""

from __future__ import annotations

import math
import os
from collections.abc import Mapping
from dataclasses import dataclass


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


def env_number(env: Mapping[str, str], name: str, default: float, *, minimum: float, integer: bool = False) -> float:
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


@dataclass(frozen=True)
class JwksSettings:
    """Live-JWKS cache bounds (seconds), used only when ``ALES_OIDC_CONFIG`` has a ``jwks_uri``."""

    ttl: float = 300.0  # ALES_OIDC_JWKS_TTL: how long a fetched key set is trusted without refetching
    min_refresh: float = 30.0  # ALES_OIDC_JWKS_MIN_REFRESH: minimum gap between fetch attempts
    max_stale: float = 3600.0  # ALES_OIDC_JWKS_MAX_STALE: longest the cache is served after fetches start failing

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
    ) -> Settings:
        e = os.environ if env is None else env
        mode = enforce_workloads if enforce_workloads is not None else (e.get("ALES_ENFORCE_WORKLOADS") or "auto")
        mode = mode.strip().lower()
        if mode not in ENFORCE_WORKLOADS_MODES:
            raise ConfigError(f"ALES_ENFORCE_WORKLOADS must be one of {ENFORCE_WORKLOADS_MODES}, got {mode!r}")
        return cls(
            approval_allow_self=(
                env_bool(e, "ALES_APPROVAL_ALLOW_SELF") if approval_allow_self is None else bool(approval_allow_self)
            ),
            enforce_workloads=mode,
            require_signatures=(
                env_bool(e, "ALES_REQUIRE_SIGNATURES") if require_signatures is None else bool(require_signatures)
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
