"""OWASP Agent Control Standard (ACS)-style hook adapter.

Version pin: targets ACS draft hook semantics, adapter contract v0. The ACS specification is pre-1.0 and
was deliberately NOT consulted over the network; this module implements against the self-contained model
below. When ACS stabilises, only the wire names/shapes in this file should need to change.

Hook model (adapter contract v0)
--------------------------------
Every hook receives ``ctx``, a mapping with ALL of ``tenant``, ``principal`` (``{"id": str, "type"?: str}``),
``purpose``, ``session_id``, ``agent_id`` (non-empty strings), and optionally ``active_context_ids`` (the
session's taint: a list of context-id strings or ``{"context_id", "version"?}`` mappings). Every hook
returns a :class:`HookDecision` ``(allow, reasons, required_action, data)`` with ``required_action`` one of
``"none"``, ``"session_reset"``, ``"redact"``.

===========================  ==============================================  ===========================
hook                         ALES call                                       outcome
===========================  ==============================================  ===========================
before_knowledge_retrieval   SessionTaint ``enforce`` (re-authorize the       deny + session_reset if the
(ctx)                        session's prior exposure)                        session depends on revoked data
after_knowledge_retrieval    ``guard_retrieval`` over ``results``             allow; ``redact`` + filtered
(ctx, results)               (items: ``{"context_id", "version"?, ...}``)     ``data["results"]`` if any blocked
before_memory_read           ``guard_memory_read`` over ``keys`` (str         as above, ``data["keys"]``
(ctx, keys)                  context ids or ``{"context_id", "version"?,
                             "key"?}``)
after_memory_write           ``register_derivation`` (kind ``memory``), one   allow; ``data["registered"]`` lists
(ctx, entries)               per entry ``{"key", "content"}``; parents are    ``{key, context_id, version}`` to
                             ``ctx["active_context_ids"]`` (else the          persist beside the entry (needed
                             session's recorded taint)                        by before_memory_read)
before_tool_call             ``enforce(session)`` (after merging              deny + session_reset if revoked
(ctx, tool, args)            ``active_context_ids`` into the taint)
before_message_send          same as before_tool_call                         same
(ctx, message)
===========================  ==============================================  ===========================

Fail closed: malformed payloads raise :class:`AcsPayloadError` from the direct hook methods; the wire
dispatcher :meth:`AcsContextGuard.handle` never raises and returns a deny decision carrying
``error = {"code": "UNKNOWN_HOOK" | "INVALID_PAYLOAD" | "INTERNAL_ERROR", ...}``. A tenant different from
the client's tenant is denied (``TENANT_MISMATCH``). Any error talking to the control plane while
enforcing is a deny (``ENFORCEMENT_ERROR``), never a silent allow.

Unmediated (not seen by this adapter, see ``coverage.py``): direct store writes, reads that bypass the
hooks, and the *content* of tool arguments and messages (only session dependence is checked; there is no
DLP). A hook the host runtime never calls is never enforced.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ales_sdk.client import InvariantClient
from ales_sdk.envelope import new_derivative
from ales_sdk.errors import AlesError
from ales_sdk.session_taint import enforce
from ales_sdk.wrappers import guard_memory_read, guard_retrieval

CONTRACT = "acs-draft/adapter-v0"
REQUIRED_ACTIONS = ("none", "session_reset", "redact")
HOOKS = (
    "before_knowledge_retrieval",
    "after_knowledge_retrieval",
    "before_memory_read",
    "after_memory_write",
    "before_tool_call",
    "before_message_send",
)
_CTX_FIELDS = ("tenant", "principal", "purpose", "session_id", "agent_id")
# hook -> (required payload fields besides ctx)
_PAYLOAD_FIELDS: dict[str, tuple[str, ...]] = {
    "before_knowledge_retrieval": (),
    "after_knowledge_retrieval": ("results",),
    "before_memory_read": ("keys",),
    "after_memory_write": ("entries",),
    "before_tool_call": ("tool", "args"),
    "before_message_send": ("message",),
}


class AcsPayloadError(ValueError):
    """A hook payload or context is malformed (the caller must treat the hook as denied)."""


@dataclass
class HookDecision:
    allow: bool
    reasons: list[str] = field(default_factory=list)
    required_action: str = "none"
    data: dict[str, Any] = field(default_factory=dict)
    error: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if self.required_action not in REQUIRED_ACTIONS:
            raise ValueError(f"required_action must be one of {REQUIRED_ACTIONS}")

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "allow": self.allow,
            "reasons": list(self.reasons),
            "required_action": self.required_action,
            "data": self.data,
        }
        if self.error:
            d["error"] = self.error
        return d


def _str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise AcsPayloadError(f"{name} must be a non-empty string")
    return value


def _validate_ctx(ctx: Any) -> dict[str, Any]:
    if not isinstance(ctx, Mapping):
        raise AcsPayloadError("ctx must be an object")
    missing = [f for f in _CTX_FIELDS if f not in ctx]
    if missing:
        raise AcsPayloadError(f"ctx missing required fields: {missing}")
    unknown = set(ctx) - set(_CTX_FIELDS) - {"active_context_ids"}
    if unknown:
        raise AcsPayloadError(f"ctx has unknown fields: {sorted(unknown)}")
    result = {f: ctx[f] for f in _CTX_FIELDS}
    for f in ("tenant", "purpose", "session_id", "agent_id"):
        _str(result[f], f"ctx.{f}")
    p = result["principal"]
    if not isinstance(p, Mapping):
        raise AcsPayloadError("ctx.principal must be an object")
    _str(p.get("id"), "ctx.principal.id")
    if "type" in p:
        _str(p["type"], "ctx.principal.type")
    result["principal"] = {"id": p["id"], "type": p.get("type", "user")}
    result["active_context_ids"] = _refs(ctx.get("active_context_ids", []), "ctx.active_context_ids")
    return result


def _refs(value: Any, name: str) -> list[tuple[str, str | None, str | None]]:
    """Normalise a list of context-id strings / ``{"context_id", "version"?, "key"?}`` to (id, version, key)."""
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise AcsPayloadError(f"{name} must be a list")
    result: list[tuple[str, str | None, str | None]] = []
    for i, v in enumerate(value):
        if isinstance(v, str):
            result.append((_str(v, f"{name}[{i}]"), None, None))
        elif isinstance(v, Mapping):
            version = v.get("version")
            if version is not None and not isinstance(version, str):
                raise AcsPayloadError(f"{name}[{i}].version must be a string")
            key = v.get("key")
            if key is not None and not isinstance(key, str):
                raise AcsPayloadError(f"{name}[{i}].key must be a string")
            result.append((_str(v.get("context_id"), f"{name}[{i}].context_id"), version, key))
        else:
            raise AcsPayloadError(f"{name}[{i}] must be a string or an object")
    return result


class AcsContextGuard:
    """Maps ACS-style hooks onto ALES authorize / register / session-taint calls."""

    def __init__(self, client: InvariantClient) -> None:
        self.client = client

    def _ctx(self, ctx: Any) -> tuple[dict[str, Any], HookDecision | None]:
        c = _validate_ctx(ctx)
        if c["tenant"] != self.client.tenant_id:
            return c, HookDecision(False, ["TENANT_MISMATCH"])
        return c, None

    def _sync_active(self, c: Mapping[str, Any]) -> None:
        """Merge the host-declared active context into the session taint so it is re-authorized."""
        active = c["active_context_ids"]
        if active:
            self.client.session_taint.record(
                c["session_id"],
                [context_id for context_id, _, _ in active],
                versions={context_id: version for context_id, version, _ in active},
                principal=c["principal"],
                purpose=c["purpose"],
            )

    def _session_decision(self, c: Mapping[str, Any]) -> HookDecision:
        try:
            self._sync_active(c)
            tv = enforce(c["session_id"], self.client)
        except AlesError as e:
            return HookDecision(False, ["ENFORCEMENT_ERROR", type(e).__name__], "session_reset")
        if not tv.reset_required:
            return HookDecision(True, ["OK"], "none", {"checked": tv.checked})
        reasons: list[str] = []
        for v in tv.revoked:
            reasons += [r for r in v.reason if r not in reasons]
        if tv.unverifiable:
            reasons.append("UNVERIFIABLE_EXPOSURE")
        return HookDecision(
            False,
            reasons or ["SESSION_DEPENDS_ON_REVOKED_CONTEXT"],
            "session_reset",
            {
                "revoked_context_ids": [v.context_id for v in tv.revoked],
                "unverifiable_context_ids": list(tv.unverifiable),
            },
        )

    def before_knowledge_retrieval(self, ctx: Any) -> HookDecision:
        c, deny = self._ctx(ctx)
        return deny or self._session_decision(c)

    def after_knowledge_retrieval(self, ctx: Any, results: Any) -> HookDecision:
        c, deny = self._ctx(ctx)
        if deny:
            return deny
        items = self._items(results, "results")
        return self._filter(c, items, results, "results", guard_retrieval)

    def before_memory_read(self, ctx: Any, keys: Any) -> HookDecision:
        c, deny = self._ctx(ctx)
        if deny:
            return deny
        items = self._items(keys, "keys")
        return self._filter(c, items, keys, "keys", guard_memory_read)

    @staticmethod
    def _items(value: Any, name: str) -> list[tuple[str, str | None, str | None]]:
        if name == "results":  # results are arbitrary objects; each must carry a context_id
            if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
                raise AcsPayloadError("results must be a list")
            for i, r in enumerate(value):
                if not isinstance(r, Mapping):
                    raise AcsPayloadError(f"results[{i}] must be an object")
        return _refs(value, name)

    def _filter(
        self,
        c: Mapping[str, Any],
        refs: list[tuple[str, str | None, str | None]],
        original: Sequence[Any],
        field_name: str,
        guard: Callable[..., Any],
    ) -> HookDecision:
        if not refs:
            return HookDecision(True, ["OK"], "none", {field_name: []})
        pairs = list(zip(original, refs, strict=True))
        try:
            allowed, blocked = guard(
                self.client,
                c["principal"],
                c["purpose"],
                pairs,
                lambda p: p[1][0],
                version_getter=lambda p: p[1][1],
                agent_id=c["agent_id"],
                session_id=c["session_id"],
            )
        except AlesError as e:
            return HookDecision(False, ["ENFORCEMENT_ERROR", type(e).__name__], "none", {field_name: []})
        result = [p[0] for p in allowed]
        if not blocked:
            return HookDecision(True, ["OK"], "none", {field_name: result})
        reasons: list[str] = []
        for b in blocked:
            reasons += [r for r in b.reasons if r not in reasons]
        return HookDecision(
            True,
            reasons,
            "redact",
            {
                field_name: result,
                "blocked": [
                    {"context_id": b.context_id, "decision": b.decision, "reasons": list(b.reasons)}
                    for b in blocked
                ],
            },
        )

    def after_memory_write(self, ctx: Any, entries: Any) -> HookDecision:
        c, deny = self._ctx(ctx)
        if deny:
            return deny
        if isinstance(entries, (str, bytes)) or not isinstance(entries, Sequence):
            raise AcsPayloadError("entries must be a list")
        for i, e in enumerate(entries):
            if not isinstance(e, Mapping):
                raise AcsPayloadError(f"entries[{i}] must be an object")
            _str(e.get("key"), f"entries[{i}].key")
            if not isinstance(e.get("content"), str):
                raise AcsPayloadError(f"entries[{i}].content must be a string")
        sid = c["session_id"]
        declared = c["active_context_ids"]
        if declared:
            parents = [
                {"context_id": context_id, "object_version": version or "1"}
                for context_id, version, _ in declared
            ]
        else:
            parents = [
                {"context_id": x.context_id, "object_version": x.version or "1"}
                for x in self.client.session_taint.exposures_for(sid)
            ]
            parents = list({p["context_id"]: p for p in parents}.values())
        if not parents:
            return HookDecision(True, ["NO_ACTIVE_CONTEXT"], "none", {"registered": []})
        registered: list[dict[str, str]] = []
        try:
            for e in entries:
                env = new_derivative(
                    "memory",
                    parents,
                    self.client.tenant_id,
                    f"memory:{e['key']}",
                    e["content"],
                    source_system="acs-memory",
                )
                self.client.register_derivation(env)
                registered.append(
                    {"key": e["key"], "context_id": env["context_id"], "version": env["object_version"]}
                )
        except AlesError as exc:
            return HookDecision(
                False,
                ["REGISTRATION_FAILED", type(exc).__name__],
                "session_reset",
                {"registered": registered},
            )
        return HookDecision(True, ["OK"], "none", {"registered": registered})

    def before_tool_call(self, ctx: Any, tool: Any, args: Any) -> HookDecision:
        c, deny = self._ctx(ctx)
        _str(tool, "tool")
        if not isinstance(args, Mapping):
            raise AcsPayloadError("args must be an object")
        return deny or self._session_decision(c)

    def before_message_send(self, ctx: Any, message: Any) -> HookDecision:
        c, deny = self._ctx(ctx)
        if not isinstance(message, (str, Mapping)):
            raise AcsPayloadError("message must be a string or an object")
        return deny or self._session_decision(c)

    def handle(self, hook_name: Any, payload: Any) -> HookDecision:
        """Wire-style entry: ``payload = {"ctx": {...}, <hook fields>}``. Never raises; fails closed."""
        if not isinstance(hook_name, str) or hook_name not in HOOKS:
            return _error("UNKNOWN_HOOK", f"unknown hook {hook_name!r}; expected one of {list(HOOKS)}")
        if not isinstance(payload, Mapping):
            return _error("INVALID_PAYLOAD", "payload must be an object")
        want = ("ctx", *_PAYLOAD_FIELDS[hook_name])
        missing = [f for f in want if f not in payload]
        extra = sorted(set(payload) - set(want))
        if missing or extra:
            return _error("INVALID_PAYLOAD", f"missing fields {missing}, unexpected fields {extra}")
        method = getattr(self, hook_name)
        try:
            decision: HookDecision = method(**{f: payload[f] for f in want})
            return decision
        except AcsPayloadError as e:
            return _error("INVALID_PAYLOAD", str(e))
        except Exception as e:  # noqa: BLE001 - the dispatcher must fail closed on anything
            return _error("INTERNAL_ERROR", type(e).__name__)


def _error(code: str, message: str) -> HookDecision:
    return HookDecision(False, [code], "none", error={"code": code, "message": message})
