"""Shared startup-hardening rules, used by BOTH ``create_app`` and ``python -m ales_server.preflight``.

Keeping the rules in one place means the preflight can never disagree with what the server will
actually refuse to start on.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.pool import StaticPool

from .config import Settings, env_bool

if TYPE_CHECKING:
    from .auth import Authenticator

log = logging.getLogger("ales.server")

DENY_ONLY_WARNING = (
    "ALES_PURGE_POLICY=deny-only: use-time denial only: revoked bytes remain in stores until purged externally. "
    "Safety of decisions is unaffected (tombstones); physical erasure is NOT performed by this server."
)


def make_engine(database_url: str, *, connect_timeout: int | None = None):
    url = make_url(database_url)
    if url.get_backend_name() == "sqlite":
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if url.database in (None, "", ":memory:"):
            kwargs["poolclass"] = StaticPool  # one shared connection so the memory DB persists
        return create_engine(database_url, **kwargs)
    extra: dict = {"connect_args": {"connect_timeout": connect_timeout}} if connect_timeout else {}
    return create_engine(database_url, pool_pre_ping=True, **extra)


def is_memory_sqlite(database_url: str) -> bool:
    url = make_url(database_url)
    return url.get_backend_name() == "sqlite" and url.database in (None, "", ":memory:")


def is_sqlite(database_url: str) -> bool:
    return make_url(database_url).get_backend_name() == "sqlite"


def purge_targets_configured(e: Mapping[str, str]) -> bool:
    return bool((e.get("ALES_PURGE_TARGETS") or "").strip())


def purge_policy_issue(e: Mapping[str, str], settings: Settings) -> str | None:
    """A contradictory purge policy (any environment): deny-only while purge targets are configured."""
    if settings.purge_policy == "deny-only" and purge_targets_configured(e):
        return "ALES_PURGE_POLICY=deny-only contradicts ALES_PURGE_TARGETS: unset one of them"
    return None


def production_violations(
    e: Mapping[str, str],
    settings: Settings,
    auth: Authenticator,
    *,
    url: str,
    allow_anonymous: bool | None,
    key_material: object,
    handlers_supplied: bool = False,
) -> list[str]:
    """Every reason a production (``ALES_ENV=production``) process must refuse to start, all at once."""
    bad: list[str] = []
    if (auth.registry is None or len(auth.registry) == 0) and auth.oidc is None:
        bad.append("no authentication configured: set ALES_TOKENS / ALES_TOKENS_FILE and/or ALES_OIDC_CONFIG")
    if e.get("ALES_DEV_ALLOW_ANONYMOUS") is not None or allow_anonymous:
        bad.append("ALES_DEV_ALLOW_ANONYMOUS must not be set at all in production")
    if not settings.require_signatures:
        if env_bool(e, "ALES_ALLOW_UNSIGNED_INGRESS"):
            log.warning(
                "ALES_ALLOW_UNSIGNED_INGRESS=1: production is accepting UNSIGNED envelopes and revocations "
                "(ALES_REQUIRE_SIGNATURES is off). Explicit operator override."
            )
        else:
            bad.append("ALES_REQUIRE_SIGNATURES must be on (or set ALES_ALLOW_UNSIGNED_INGRESS=1 to accept unsigned ingress)")
    if not key_material:
        if env_bool(e, "ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY"):
            log.warning(
                "ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY=1: production signs snapshots with a per-process key; offline "
                "verification will break across restarts and replicas."
            )
        else:
            bad.append("ALES_SNAPSHOT_KEY is required (or set ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY=1 to accept a per-process key)")
    if is_sqlite(url):
        if env_bool(e, "ALES_ALLOW_SQLITE"):
            log.warning(
                "ALES_ALLOW_SQLITE=1: production is running on SQLite. Single node only, no horizontal scale-out, "
                "no row locking. Explicit operator override."
            )
        else:
            bad.append("DATABASE_URL is SQLite: use Postgres (or set ALES_ALLOW_SQLITE=1 to accept a single-node SQLite)")
    if settings.enforce_workloads == "off":
        bad.append("ALES_ENFORCE_WORKLOADS=off is not allowed in production (use 'strict' or 'auto')")
    if settings.purge_policy == "purge" and not purge_targets_configured(e) and not handlers_supplied:
        bad.append(
            "ALES_PURGE_POLICY=purge (the production default) but ALES_PURGE_TARGETS is not set: revoked bytes would "
            "never be erased from downstream stores. Configure ALES_PURGE_TARGETS, or set ALES_PURGE_POLICY=deny-only "
            "to accept use-time denial only"
        )
    issue = purge_policy_issue(e, settings)
    if issue:
        bad.append(issue)
    return bad


def dev_unsafe_settings(settings: Settings, auth: Authenticator, *, url: str, key_material: object) -> list[str]:
    unsafe: list[str] = []
    if auth.allow_anonymous:
        unsafe.append("anonymous authentication (every caller has ALL roles and picks its tenant)")
    if not key_material:
        unsafe.append("ephemeral snapshot key (per-process; offline verification breaks across restarts/replicas)")
    if not settings.require_signatures:
        unsafe.append("signature ingress OFF (unsigned envelopes and revocations are accepted)")
    if is_sqlite(url):
        unsafe.append("SQLite database (single node, not for production)")
    if settings.enforce_workloads == "off":
        unsafe.append("workload/grant enforcement OFF (agent_id is an unverified label)")
    if settings.approval_allow_self:
        unsafe.append("approval separation of duties DISABLED")
    return unsafe
