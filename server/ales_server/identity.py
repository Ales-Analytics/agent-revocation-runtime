"""Entitlement providers: who is this principal *in the customer's directory* (SPEC v0.5 identity federation).

Three interfaces, deliberately separate (see ``docs/identity.md``):

* identity provider    - "who is calling?"  -> ``auth.py`` / ``oidc.py`` (bearer token or OIDC JWT).
* entitlement provider - "which groups / roles does this principal hold?" -> this module.
* source authorization - "may this identity touch this source?" -> the connector ACL model; it reaches the
  resolver as the envelope's ``principal_scope`` / ``purpose_scope`` (never as connector credentials).

An :class:`EntitlementProvider` answers ``resolve(tenant, principal_id, issuer) -> Entitlements``. The authorize
path resolves entitlements SERVER-side and hands the groups to the resolver (``AuthorizeRequest.groups``);
callers cannot assert their own groups once a provider is configured (see :func:`resolve_for_request`).

Provider semantics
------------------
* **Authority mode** is declared per provider (``authority_mode``): ``event-maintained`` (static document,
  invalidated by ``POST /v1/entitlements/reload``) or ``bounded-assertion`` (OIDC claim, valid until the
  token's ``exp``). Neither is a live check; there is no live entitlement provider in this increment.
* **Revision**: every answer carries an opaque ``revision``. It is written to the audit detail of every
  decision (``entitlement_revision``) so an auditor can tell which membership state a decision saw.
* **expires_at**: when set, the decision's ``valid_until`` is capped at it, so a client never caches an
  ALLOW past the instant the membership assertion itself lapses.
* **Failure**: a *required* provider that raises (or cannot interpret the identity) makes every object whose
  verdict could have been changed by group membership UNKNOWN (``ENTITLEMENT_UNAVAILABLE``); an *optional*
  one is recorded and treated as "no groups". A provider that has no statement about a principal returns
  ``None`` ("not applicable"): that is not a failure. ``ALLOW`` is never produced from a failed lookup
  because groups only ever WIDEN a principal scope, so an ALLOW computed with fewer groups stays an ALLOW and
  a DENY-by-scope computed with unknown groups is the only verdict that becomes UNKNOWN.
* Providers are called synchronously and MUST enforce their own timeouts; the two shipped here are local.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from ales_core import (
    AuthorizeRequest,
    Decision,
    ReasonCode,
    canonicalize,
)
from ales_core.providers import rebuild_response

from .config import ConfigError, env_bool

if TYPE_CHECKING:  # pragma: no cover
    from .auth import Identity

log = logging.getLogger("ales.server.identity")

AUTHORITY_MODES = ("live-check", "event-maintained", "bounded-assertion")
MAX_AUDIT_GROUPS = 64
AUDIT_CLIP = 128
_RFC3339 = "%Y-%m-%dT%H:%M:%S.%fZ"


class EntitlementError(Exception):
    """A provider could not produce an answer for a principal it is responsible for."""


@dataclass(frozen=True)
class Entitlements:
    groups: tuple[str, ...]
    revision: str
    expires_at: datetime | None = None
    source: str = ""


@runtime_checkable
class EntitlementProvider(Protocol):
    name: str
    required: bool
    authority_mode: str

    def resolve(
        self, tenant: str, principal_id: str, issuer: str | None, *, caller: Identity | None = None
    ) -> Entitlements | None:
        """The principal's entitlements, ``None`` when this provider has no statement about it, or raise
        :class:`EntitlementError`. ``caller`` is the authenticated API caller (token-bound providers use it)."""
        ...


def _digest(obj: Any) -> str:
    return hashlib.sha256(canonicalize(obj)).hexdigest()


def _clean_groups(raw: Any, where: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not all(isinstance(g, str) and g and len(g) <= 512 for g in raw):
        raise ConfigError(f"{where} must be a list of non-empty group names (at most 512 characters each)")
    return tuple(sorted(set(raw)))


# ---------------------------------------------------------------------------------------- static provider
class StaticEntitlements:
    """``{tenant: {principal: [groups]}}`` from ``ALES_ENTITLEMENTS`` (inline JSON) or ``ALES_ENTITLEMENTS_FILE``.

    LOCAL / DEMO provider and the reference for the event-maintained mode: membership changes only when an
    operator edits the document AND calls ``POST /v1/entitlements/reload`` (which bumps the tenant epoch for
    every tenant whose entries changed). Each replica holds its own in-memory copy; reload every replica.

    Principal keys: a bare ``"alice"`` (for requests with no issuer) or ``"iss:<issuer>:alice"`` (for
    requests carrying ``principal.issuer``). A request WITH an issuer never matches a bare key and vice
    versa: two systems that both name a person "alice" are different people, so an unqualified directory
    entry must not silently apply to a qualified principal.
    """

    name = "static"
    authority_mode = "event-maintained"

    def __init__(self, loader: Callable[[], dict[str, dict[str, tuple[str, ...]]]], *, required: bool = True) -> None:
        self._loader = loader
        self.required = required
        self._lock = threading.Lock()
        self._doc = loader()  # ConfigError at startup is fatal
        self._revs = {t: _digest(self._slice(t, self._doc)) for t in self._doc}

    @staticmethod
    def _slice(tenant: str, doc: Mapping[str, Any]) -> dict[str, Any]:
        return {"tenant": tenant, "entries": {k: list(v) for k, v in doc.get(tenant, {}).items()}}

    @classmethod
    def from_env(cls, env: Mapping[str, str], *, required: bool = True) -> StaticEntitlements | None:
        inline = (env.get("ALES_ENTITLEMENTS") or "").strip()
        path = (env.get("ALES_ENTITLEMENTS_FILE") or "").strip()
        if not inline and not path:
            return None
        if inline and path:
            raise ConfigError("set only one of ALES_ENTITLEMENTS and ALES_ENTITLEMENTS_FILE")

        def load() -> dict[str, dict[str, tuple[str, ...]]]:
            if path:
                try:
                    text = Path(path).read_text(encoding="utf-8")
                except OSError as exc:
                    raise ConfigError(f"cannot read ALES_ENTITLEMENTS_FILE {path!r}: {exc}") from exc
                source = "ALES_ENTITLEMENTS_FILE"
            else:
                text, source = (env.get("ALES_ENTITLEMENTS") or "").strip(), "ALES_ENTITLEMENTS"
            return parse_static_document(text, source)

        return cls(load, required=required)

    def reload(self) -> frozenset[str]:
        """Re-read the source; return the tenants whose entries changed. A bad document raises
        :class:`ConfigError` and the previous one stays in force."""
        new = self._loader()
        with self._lock:
            old, old_revs = self._doc, self._revs
            new_revs = {t: _digest(self._slice(t, new)) for t in new}
            empty = {t: _digest(self._slice(t, {})) for t in set(old) | set(new)}
            changed = {
                t for t in set(old) | set(new) if new_revs.get(t, empty[t]) != old_revs.get(t, empty[t])
            }
            self._doc, self._revs = new, new_revs
        return frozenset(changed)

    def revision_for(self, tenant: str) -> str:
        with self._lock:
            rev = self._revs.get(tenant)
        return rev if rev is not None else _digest(self._slice(tenant, {}))

    def resolve(
        self, tenant: str, principal_id: str, issuer: str | None, *, caller: Identity | None = None
    ) -> Entitlements | None:
        with self._lock:
            doc = self._doc
        rev = self.revision_for(tenant)
        key = principal_id if issuer is None else f"iss:{issuer}:{principal_id}"
        return Entitlements(groups=tuple(doc.get(tenant, {}).get(key, ())), revision=rev, source=self.name)


def parse_static_document(text: str, source: str) -> dict[str, dict[str, tuple[str, ...]]]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ConfigError(f"{source} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{source} must be a JSON object {{tenant: {{principal: [groups]}}}}")
    out: dict[str, dict[str, tuple[str, ...]]] = {}
    for tenant, entries in data.items():
        if not tenant or tenant.endswith(":verify"):
            raise ConfigError(f"{source}: invalid tenant id {tenant!r}")
        if not isinstance(entries, dict):
            raise ConfigError(f"{source}: tenant {tenant!r} must map principal -> [groups]")
        out[tenant] = {}
        for principal, groups in entries.items():
            if not principal:
                raise ConfigError(f"{source}: empty principal key under tenant {tenant!r}")
            out[tenant][principal] = _clean_groups(groups, f"{source}: groups of {principal!r}")
    return out


# ------------------------------------------------------------------------------------- OIDC claim provider
class OidcClaimEntitlements:
    """Groups carried in a verified OIDC token (``claim_mapping.groups``): a BOUNDED ASSERTION.

    Applies only when the principal in the request IS the authenticated token subject (and, when the request
    names an issuer, that issuer is the token's). A service token acting for another user can say nothing
    about that user's groups, so the answer is ``None`` (not applicable) - never an invented empty list.
    The assertion is only as fresh as the token: ``expires_at`` is the token's ``exp`` and caps the
    decision's ``valid_until``. Entra "group overage" (``_claim_names`` lists the groups claim, the token
    omits the groups) is *unresolvable*: raises :class:`EntitlementError`.
    """

    name = "oidc-claim"
    authority_mode = "bounded-assertion"

    def __init__(self, *, required: bool = True) -> None:
        self.required = required

    def resolve(
        self, tenant: str, principal_id: str, issuer: str | None, *, caller: Identity | None = None
    ) -> Entitlements | None:
        if caller is None or caller.anonymous or caller.issuer is None or (caller.groups is None and not caller.groups_unresolved):
            return None
        if caller.subject != principal_id or (issuer is not None and issuer != caller.issuer):
            return None
        if caller.groups_unresolved or caller.groups is None:  # (groups None + not unresolved was filtered above)
            raise EntitlementError("groups claim could not be resolved from the token (overage or absent mapping)")
        groups = tuple(sorted(set(caller.groups)))
        rev = _digest({"iss": caller.issuer, "sub": caller.subject, "groups": list(groups)})
        exp = datetime.fromtimestamp(caller.token_exp, UTC) if caller.token_exp is not None else None
        return Entitlements(groups=groups, revision=rev, expires_at=exp, source=self.name)


# --------------------------------------------------------------------------------------------- outcome
@dataclass(frozen=True)
class EntitlementOutcome:
    """What the authorize path learned about the principal's entitlements (not a decision)."""

    groups: tuple[str, ...] = ()
    revision: str | None = None
    expires_at: datetime | None = None
    status: str = "not_configured"  # resolved | none | unavailable | optional_unavailable | caller_asserted | not_configured
    sources: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    authority_modes: tuple[str, ...] = ()

    @property
    def unavailable(self) -> bool:
        return self.status == "unavailable"

    def audit_extra(self, issuer: str | None) -> dict[str, Any]:
        """Identifier-only audit fields (group names clipped; no claims, tokens or free text)."""
        out: dict[str, Any] = {}
        if issuer is not None:
            out["principal_issuer"] = issuer[:AUDIT_CLIP]
        if self.status == "not_configured":
            return out
        out["entitlement_status"] = self.status
        if self.revision is not None:
            out["entitlement_revision"] = self.revision
        if self.sources:
            out["entitlement_sources"] = list(self.sources)
        if self.failed:
            out["entitlement_failed"] = list(self.failed)
        if self.authority_modes:
            out["entitlement_authority"] = list(self.authority_modes)
        if self.groups:
            out["groups"] = [g[:AUDIT_CLIP] for g in self.groups[:MAX_AUDIT_GROUPS]]
            if len(self.groups) > MAX_AUDIT_GROUPS:
                out["groups_truncated"] = len(self.groups)
        if self.expires_at is not None:
            out["entitlement_expires_at"] = self.expires_at.astimezone(UTC).strftime(_RFC3339)
        return out


class CallerGroupsRejected(Exception):
    """The caller asserted ``groups`` where the server resolves them itself (or in production)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class EntitlementResolver:
    """The configured providers, resolved in order; groups are the union of every applicable answer."""

    providers: list[EntitlementProvider] = field(default_factory=list)

    def resolve(self, tenant: str, principal_id: str, issuer: str | None, caller: Identity | None) -> EntitlementOutcome:
        groups: set[str] = set()
        revs: list[str] = []
        sources: list[str] = []
        failed: list[str] = []
        modes: list[str] = []
        expiries: list[datetime] = []
        unavailable = False
        for p in self.providers:
            try:
                ent = p.resolve(tenant, principal_id, issuer, caller=caller)
            except Exception as exc:  # noqa: BLE001 - any provider failure is "unresolvable", never an exception path
                log.warning("entitlement provider %s failed: %s", p.name, type(exc).__name__)
                failed.append(p.name)
                unavailable = unavailable or p.required
                continue
            if ent is None:
                continue
            groups.update(ent.groups)
            revs.append(f"{p.name}:{ent.revision}")
            sources.append(p.name)
            modes.append(p.authority_mode)
            if ent.expires_at is not None:
                expiries.append(ent.expires_at)
        revision = hashlib.sha256("|".join(sorted(revs)).encode()).hexdigest() if revs else None
        if unavailable:
            status = "unavailable"
        elif failed:
            status = "optional_unavailable"
        elif sources:
            status = "resolved"
        else:
            status = "none"
        return EntitlementOutcome(
            groups=tuple(sorted(groups)),
            revision=revision,
            expires_at=min(expiries) if expiries else None,
            status=status,
            sources=tuple(sources),
            failed=tuple(failed),
            authority_modes=tuple(sorted(set(modes))),
        )


def resolve_for_request(
    resolver: EntitlementResolver | None,
    req: AuthorizeRequest,
    tenant: str,
    caller: Identity,
    *,
    production: bool,
) -> tuple[AuthorizeRequest, EntitlementOutcome]:
    """Return the request the resolver should see (server-resolved ``groups``) and the entitlement outcome.

    * provider configured: caller-supplied ``groups`` are REJECTED (:class:`CallerGroupsRejected`); the
      request carries only what the providers returned (``[]`` when none applies or an optional one failed).
    * no provider: caller ``groups`` pass through for local testing and are flagged ``caller_asserted`` in
      the audit trail; in production they are rejected (a caller must not self-assert group membership).
    """
    if resolver is None or not resolver.providers:
        if req.groups:
            if production:
                raise CallerGroupsRejected("production_no_provider")
            return req, EntitlementOutcome(
                groups=tuple(sorted(set(req.groups))), status="caller_asserted", sources=("caller",)
            )
        return req, EntitlementOutcome()
    if req.groups:
        raise CallerGroupsRejected("caller_groups_with_provider")
    outcome = resolver.resolve(tenant, req.principal.id, req.principal.issuer, caller)
    return req.model_copy(update={"groups": list(outcome.groups)}), outcome


def restrict_decision(out: Any, outcome: EntitlementOutcome) -> None:
    """Fold the entitlement outcome into ``out`` (an ``AuthorizeOutcome``): never loosens an ALLOW.

    * ``unavailable`` (a required provider failed): a verdict that is a DENY *solely* because the principal
      is not in scope (the one thing group membership could have changed) becomes UNKNOWN with
      ``ENTITLEMENT_UNAVAILABLE`` kept beside ``PRINCIPAL_NOT_IN_SCOPE``. Other denials stand; ALLOW stands
      (more groups can only widen scope). Grant-missing denials are workload facts, not group facts.
    * ``expires_at``: ALLOW / REFRESH verdicts get ``valid_until`` capped at it.
    """
    resp = out.response
    verdicts = list(resp.objects)
    changed = False
    if outcome.unavailable and not getattr(out, "grant_missing", False):
        for i, v in enumerate(verdicts):
            if v.decision == Decision.DENY and v.reason == [ReasonCode.PRINCIPAL_NOT_IN_SCOPE]:
                verdicts[i] = v.model_copy(
                    update={
                        "decision": Decision.UNKNOWN,
                        "reason": [ReasonCode.ENTITLEMENT_UNAVAILABLE, ReasonCode.PRINCIPAL_NOT_IN_SCOPE],
                    }
                )
                changed = True
    if outcome.expires_at is not None:
        cap = outcome.expires_at.astimezone(UTC).strftime(_RFC3339)
        for i, v in enumerate(verdicts):
            if v.decision in (Decision.ALLOW, Decision.REFRESH) and (v.valid_until is None or cap < v.valid_until):
                verdicts[i] = v.model_copy(update={"valid_until": cap})
                changed = True
    if changed:
        out.response = rebuild_response(resp, verdicts)


def build_entitlements(
    env: Mapping[str, str], oidc: Any = None, *, required_default: bool = True
) -> tuple[EntitlementResolver | None, StaticEntitlements | None]:
    """Providers from the environment (+ the OIDC verifier's groups claim). ``(None, None)`` when none."""
    required = env_bool(env, "ALES_ENTITLEMENTS_REQUIRED", default=required_default)
    providers: list[EntitlementProvider] = []
    static = StaticEntitlements.from_env(env, required=required)
    if static is not None:
        providers.append(static)
    if oidc is not None and getattr(oidc, "groups_claim", None):
        providers.append(OidcClaimEntitlements(required=bool(getattr(oidc, "groups_required", True))))
    if not providers:
        return None, None
    return EntitlementResolver(providers), static


__all__ = [
    "AUTHORITY_MODES",
    "CallerGroupsRejected",
    "EntitlementError",
    "EntitlementOutcome",
    "EntitlementProvider",
    "EntitlementResolver",
    "Entitlements",
    "OidcClaimEntitlements",
    "StaticEntitlements",
    "build_entitlements",
    "parse_static_document",
    "resolve_for_request",
    "restrict_decision",
]
