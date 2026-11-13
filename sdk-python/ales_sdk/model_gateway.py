"""Model-gateway enforcement: authorize context immediately before it is injected into a model call.

Provider-neutral: works on plain message/context lists and on any OpenAI-style
``chat.completions.create(messages=...)`` callable. No provider SDK is imported.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .client import InvariantClient
from .envelope import new_derivative
from .errors import AlesError, ConfigError, HumanReviewPending
from .fail_modes import FailMode, resolve
from .wrappers import Blocked

__all__ = [
    "DecisionSummary",
    "GatewayReceipt",
    "GuardedModelCall",
    "PreparedContext",
    "default_id_getter",
]

log = logging.getLogger("ales_sdk")

ID_KEY = "ales_context_id"
VERSION_KEY = "ales_version"


def _lookup(item: Any, key: str) -> Any:
    if isinstance(item, Mapping):
        if item.get(key) is not None:
            return item[key]
        meta = item.get("metadata")
        if isinstance(meta, Mapping):
            return meta.get(key)
        return None
    val = getattr(item, key, None)
    if val is not None:
        return val
    meta = getattr(item, "metadata", None)
    return meta.get(key) if isinstance(meta, Mapping) else None


def default_id_getter(item: Any) -> str | None:
    """ALES context id of a message/context item: ``ales_context_id`` key/attr, or in ``metadata``."""
    val = _lookup(item, ID_KEY)
    return str(val) if val is not None else None


def _version_of(item: Any) -> str | None:
    val = _lookup(item, VERSION_KEY)
    return str(val) if val is not None else None


@dataclass
class DecisionSummary:
    total: int = 0
    tracked: int = 0  # items carrying an ALES id (authorized)
    untracked: int = 0  # items with no id: passed through unchecked -- the honest coverage gap
    allowed: int = 0  # tracked items kept in the prepared context
    blocked: int = 0  # tracked items removed
    observed_only: int = 0  # kept despite a non-ALLOW decision (OBSERVE / WARN non-protected)
    offline: bool = False
    trace_id: str | None = None
    policy_version: str | None = None

    @property
    def coverage(self) -> float:
        return self.tracked / self.total if self.total else 1.0


@dataclass
class PreparedContext:
    messages: list[Any]
    blocked: list[Blocked] = field(default_factory=list)
    decision_summary: DecisionSummary = field(default_factory=DecisionSummary)
    #: (context_id, version) of tracked items that remain in ``messages`` (parents of any response)
    kept: list[tuple[str, str | None]] = field(default_factory=list)


@dataclass
class GatewayReceipt:
    """Side-channel returned with a gated model response."""

    context_id: str | None  # the registered response artifact; None if nothing tracked fed the call
    version: str | None
    blocked: list[Blocked] = field(default_factory=list)
    untracked: int = 0
    registered: bool = False


class GuardedModelCall:
    def __init__(
        self,
        client: InvariantClient,
        principal: Mapping[str, str],
        purpose: str,
        *,
        session_id: str | None = None,
        agent_id: str | None = None,
        on_human_review: str = "raise",
        tools: list[str] | None = None,
        risk: str | None = None,
    ) -> None:
        if on_human_review not in ("raise", "block_item"):
            raise ConfigError(f"on_human_review must be 'raise' or 'block_item', got {on_human_review!r}")
        self.client = client
        self.principal = principal
        self.purpose = purpose
        self.session_id = session_id
        self.agent_id = agent_id
        self.on_human_review = on_human_review
        self.tools = tools
        self.risk = risk

    @property
    def fail_mode(self) -> FailMode:
        return self.client.fail_mode

    def prepare(
        self,
        messages_or_context: Sequence[Any],
        id_getter: Callable[[Any], str | None] | None = None,
    ) -> PreparedContext:
        """Authorize every identified item in one batch and drop what may not reach the model."""
        getter = id_getter or default_id_getter
        items = list(messages_or_context)
        ids = [getter(i) for i in items]
        versions = [_version_of(i) for i in items]
        tracked = [(i, cid, v) for i, cid, v in zip(items, ids, versions, strict=True) if cid is not None]
        summary = DecisionSummary(
            total=len(items), tracked=len(tracked), untracked=len(items) - len(tracked)
        )
        if not tracked:
            return PreparedContext(list(items), [], summary, [])

        batch: dict[str, str | None] = {}
        for _, cid, v in tracked:
            batch.setdefault(cid, v)
        result = self.client.authorize(
            self.principal,
            self.purpose,
            list(batch.items()),
            agent_id=self.agent_id,
            session_id=self.session_id,
            tools=self.tools,
            risk=self.risk,
        )
        summary.offline = result.offline
        summary.trace_id = result.trace_id
        summary.policy_version = result.policy_version

        enforcing = self.fail_mode in (FailMode.ENFORCE, FailMode.BOUNDED_OFFLINE)
        pending: list[Blocked] = []
        drop: set[int] = set()
        blocked: list[Blocked] = []
        kept: list[tuple[str, str | None]] = []
        for item, cid, v in tracked:
            verdict = result.verdict_for(cid)
            decision = verdict.decision if verdict else "UNKNOWN"
            reasons = list(verdict.reason) if verdict else ["OBJECT_UNKNOWN"]
            if decision == "HUMAN_REVIEW" and enforcing:
                b = Blocked(item, cid, decision, reasons, needs_override=False)
                if self.on_human_review == "raise":
                    pending.append(b)
                else:
                    blocked.append(b)
                    drop.add(id(item))
                continue
            action = resolve(decision, self.fail_mode, None, result.lease_ok)
            if action.allow:
                kept.append((cid, (verdict.version if verdict and verdict.version else v)))
                if action.observed_only:
                    summary.observed_only += 1
            else:
                blocked.append(Blocked(item, cid, decision, reasons, action.needs_override))
                drop.add(id(item))
        if pending:
            raise HumanReviewPending(
                [b.context_id for b in pending], sorted({r for b in pending for r in b.reasons})
            )

        out = [i for i in items if id(i) not in drop]
        summary.blocked = len(blocked)
        summary.allowed = len(kept)
        if self.session_id and kept:
            self.client.session_taint.record(
                self.session_id,
                [c for c, _ in kept],
                versions=dict(kept),
                principal=self.principal,
                purpose=self.purpose,
            )
        return PreparedContext(out, blocked, summary, kept)

    def wrap_openai_compatible(
        self, create_fn: Callable[..., Any]
    ) -> Callable[..., tuple[Any, GatewayReceipt]]:
        """Wrap ``create(messages=..., **kw)``; returns ``(response, GatewayReceipt)``.

        Messages are gated via :meth:`prepare`; the response is registered as an ``artifact``
        derivative of the tracked context that was actually sent to the model.
        """

        def guarded(*args: Any, **kwargs: Any) -> tuple[Any, GatewayReceipt]:
            if args:
                raise TypeError("guarded create() takes keyword arguments only (messages=...)")
            if "messages" not in kwargs:
                raise TypeError("guarded create() requires messages=")
            prepared = self.prepare(list(kwargs.pop("messages")))
            response = create_fn(messages=prepared.messages, **kwargs)
            receipt = GatewayReceipt(None, None, prepared.blocked, prepared.decision_summary.untracked)
            parents = _dedupe(prepared.kept)
            if not parents:
                return response, receipt
            env = new_derivative(
                "artifact",
                [{"context_id": c, "object_version": v or "1"} for c, v in parents],
                self.client.tenant_id,
                f"model-response:{uuid.uuid4()}",
                _response_content(response),
                source_system="ales-model-gateway",
            )
            try:
                self.client.register_derivation(env)
            except AlesError:
                if self.fail_mode in (FailMode.ENFORCE, FailMode.BOUNDED_OFFLINE):
                    raise  # an unregistered response would escape revocation tracking: fail closed
                log.warning("could not register model response derivation", exc_info=True)
                return response, receipt
            receipt.context_id = env["context_id"]
            receipt.version = env["object_version"]
            receipt.registered = True
            return response, receipt

        return guarded


def _dedupe(kept: list[tuple[str, str | None]]) -> list[tuple[str, str | None]]:
    seen: dict[str, str | None] = {}
    for c, v in kept:
        seen.setdefault(c, v)
    return list(seen.items())


def _response_content(response: Any) -> str:
    """Best-effort text of an OpenAI-style response (dict or object); falls back to repr."""
    try:
        choices = response["choices"] if isinstance(response, Mapping) else response.choices
        first = choices[0]
        msg = first["message"] if isinstance(first, Mapping) else first.message
        content = msg["content"] if isinstance(msg, Mapping) else msg.content
        if content is not None:
            return str(content)
    except (KeyError, IndexError, AttributeError, TypeError):
        pass
    try:
        return json.dumps(response, sort_keys=True, default=repr)
    except (TypeError, ValueError):
        return repr(response)
