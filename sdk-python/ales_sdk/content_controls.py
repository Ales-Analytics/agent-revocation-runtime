"""Content-control stage (Bedrock Guardrails-compatible, provider-neutral).

A content control inspects *text* (prompt items going in, model output coming out) for content
policy: PII, toxicity, denied topics. It is orthogonal to authority: a control passing proves
nothing about whether the source may be used, and ALES authorization says nothing about content
policy. Per spec/SPEC.md "Release gate (v0.4)": content-control stages compose as obligations, a
masked output remains a derivative of its parents, and ``CONTENT_CONTROL_BLOCKED`` is a content
decision, never an authority decision.

This module imports no cloud SDK and performs no network I/O. A control sees text only when the
integrator configures one, and :class:`BedrockGuardrailControl` reaches a provider only through
the ``apply_fn`` callable the integrator supplies; that callable determines where the text is
processed and must be permitted for the data's classification.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Literal, Protocol, runtime_checkable

__all__ = [
    "BedrockGuardrailControl",
    "ContentAssessment",
    "ContentControl",
    "ContentControlPolicy",
    "SimulatedContentControl",
]

Action = Literal["none", "masked", "blocked"]
CONTENT_CONTROL_BLOCKED = "CONTENT_CONTROL_BLOCKED"


@dataclass(frozen=True)
class ContentAssessment:
    """Outcome of one control invocation. Never contains the assessed text.

    ``masked_text`` carries the control's *output* text when ``action == "masked"``; it is excluded
    from ``repr``/equality and is stripped before assessments are recorded in summaries/receipts.
    """

    action: Action
    reference: str
    provider: str
    guardrail_version: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    masked_text: str | None = field(default=None, repr=False, compare=False)

    def redacted(self) -> ContentAssessment:
        """Copy safe to record: no text of any kind."""
        return replace(self, masked_text=None)


@runtime_checkable
class ContentControl(Protocol):
    def assess_input(self, text: str) -> ContentAssessment: ...

    def assess_output(self, text: str) -> ContentAssessment: ...


def _reference(provider: str, version: str | None, action: str, detail: Mapping[str, Any]) -> str:
    blob = json.dumps(
        {"provider": provider, "version": version, "action": action, "detail": detail},
        sort_keys=True,
        separators=(",", ":"),
        default=repr,
    )
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


def _strip_text(node: Any) -> Any:
    """Drop fields that carry matched/assessed text from a provider assessment (keep types/actions)."""
    if isinstance(node, Mapping):
        return {k: _strip_text(v) for k, v in node.items() if k not in ("match", "text", "regex_match")}
    if isinstance(node, list):
        return [_strip_text(v) for v in node]
    return node


def _any_blocked(node: Any) -> bool:
    if isinstance(node, Mapping):
        return node.get("action") == "BLOCKED" or any(_any_blocked(v) for v in node.values())
    if isinstance(node, list):
        return any(_any_blocked(v) for v in node)
    return False


class BedrockGuardrailControl:
    """Wraps an ApplyGuardrail-shaped call supplied by the integrator.

    ``apply_fn(content, source)`` takes the text and ``"INPUT"``/``"OUTPUT"`` and returns a dict in
    the ApplyGuardrail response shape (``action``, ``outputs``, ``assessments``). Typically it
    closes over a boto3 ``bedrock-runtime`` client; that choice (and the region/account the text
    is sent to) is the integrator's explicit decision. Nothing here imports boto3.

    Mapping: ``NONE`` -> ``none``. ``GUARDRAIL_INTERVENED`` -> ``blocked`` if any assessment entry
    reports action ``BLOCKED`` or no replacement text is returned; otherwise ``masked`` with the
    first output text as ``masked_text``. (Bedrock returns the configured canned message as an
    output for blocks, so assessments are checked first.)
    """

    provider = "bedrock-guardrails"

    def __init__(
        self,
        apply_fn: Callable[[str, str], Mapping[str, Any]],
        guardrail_id: str,
        guardrail_version: str,
    ) -> None:
        self._apply = apply_fn
        self.guardrail_id = guardrail_id
        self.guardrail_version = guardrail_version

    def _assess(self, text: str, source: str) -> ContentAssessment:
        response = self._apply(text, source)
        assessments = _strip_text(list(response.get("assessments") or []))
        raw = [o.get("text") for o in (response.get("outputs") or []) if isinstance(o, Mapping)]
        outputs: list[str] = [o for o in raw if isinstance(o, str)]
        masked: str | None = None
        if response.get("action") != "GUARDRAIL_INTERVENED":
            action: Action = "none"
        elif _any_blocked(assessments) or not outputs:
            action = "blocked"
        else:
            action = "masked"
            masked = "".join(outputs)
        detail = {
            "guardrail_id": self.guardrail_id,
            "source": source,
            "provider_action": response.get("action"),
            "assessments": assessments,
        }
        return ContentAssessment(
            action,
            _reference(self.provider, self.guardrail_version, action, detail),
            self.provider,
            self.guardrail_version,
            detail,
            masked,
        )

    def assess_input(self, text: str) -> ContentAssessment:
        return self._assess(text, "INPUT")

    def assess_output(self, text: str) -> ContentAssessment:
        return self._assess(text, "OUTPUT")


class SimulatedContentControl:
    """TEST DOUBLE. NOT A SECURITY CONTROL.

    Regex deny/mask lists for tests and demos only. It does not detect real PII or harmful
    content and must never stand in for a production guardrail. Every assessment is labelled
    ``provider="simulated"``.
    """

    provider = "simulated"

    def __init__(
        self,
        deny: Sequence[str] = (),
        mask: Sequence[str] = (),
        replacement: str = "[MASKED]",
    ) -> None:
        self._deny = [re.compile(p) for p in deny]
        self._mask = [re.compile(p) for p in mask]
        self._replacement = replacement

    def _assess(self, text: str) -> ContentAssessment:
        denied = [p.pattern for p in self._deny if p.search(text)]
        masked_text = text
        masked_hits: list[str] = []
        for p in self._mask:
            masked_text, n = p.subn(self._replacement, masked_text)
            if n:
                masked_hits.append(p.pattern)
        if denied:
            action: Action = "blocked"
            detail: dict[str, Any] = {"deny_patterns": denied}
        elif masked_hits:
            action = "masked"
            detail = {"mask_patterns": masked_hits}
        else:
            action, detail = "none", {}
        return ContentAssessment(
            action,
            _reference(self.provider, None, action, detail),
            self.provider,
            None,
            detail,
            masked_text if action == "masked" else None,
        )

    def assess_input(self, text: str) -> ContentAssessment:
        return self._assess(text)

    def assess_output(self, text: str) -> ContentAssessment:
        return self._assess(text)


@dataclass(frozen=True)
class ContentControlPolicy:
    """What happens when a control itself fails (callable raises, provider unreachable).

    ``required=True`` (default): fail closed -> a ``blocked`` assessment, reason
    ``provider_unavailable``. ``required=False``: ``none`` with the failure recorded (exception
    class name only; messages may echo content).
    """

    required: bool = True

    def run(self, fn: Callable[[str], ContentAssessment], text: str, provider: str) -> ContentAssessment:
        try:
            return fn(text)
        except Exception as exc:  # noqa: BLE001 - any control failure is policy-governed
            detail = {
                "reason": "provider_unavailable",
                "error": type(exc).__name__,
                "required": self.required,
            }
            action: Action = "blocked" if self.required else "none"
            return ContentAssessment(
                action, _reference(provider, None, action, detail), provider, None, detail
            )
