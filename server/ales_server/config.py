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


@dataclass(frozen=True)
class Settings:
    require_signatures: bool
    max_body: int
    snapshot_lease: int
    outbox_interval: float  # seconds; 0 disables the background worker

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        require_signatures: bool | None = None,
        max_body: int | None = None,
        snapshot_lease: int | None = None,
        outbox_interval: float | None = None,
    ) -> Settings:
        e = os.environ if env is None else env
        return cls(
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
