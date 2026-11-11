"""Framework-neutral hooks that wrap LangGraph-style nodes (``state -> dict update``).

Nothing here imports langgraph. Attach to a real graph by decorating the node functions before
``add_node``::

    from langgraph.graph import StateGraph
    from ales_adapters.langgraph_middleware import guard_node, register_output

    @guard_node(client, principal, "support", id_getter=lambda d: d["context_id"],
                version_getter=lambda d: d.get("version"))
    def retrieve(state): return {"documents": search(state["question"])}

    @register_output(client, parents_key="documents", kind="summary")
    def summarize(state): return {"text": llm(state["documents"])}

    g = StateGraph(MyState); g.add_node("retrieve", retrieve); g.add_node("summarize", summarize)

``guard_node`` filters the list-valued ``documents``/``results`` keys (of the node's returned update by
default, of its input with ``phase="input"``, or both) and records session taint from
``state["session_id"]``. Blocked items are reported under ``ales_blocked``. ``register_output``
registers the node's text output as a derivative of the envelopes in ``state[parents_key]`` and
returns the new ``ales_context_id`` / ``ales_object_version`` in the update. Async nodes are supported.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ales_sdk.client import InvariantClient
from ales_sdk.envelope import new_derivative
from ales_sdk.wrappers import guard_retrieval

DEFAULT_KEYS = ("documents", "results")


def _filter_keys(
    client: InvariantClient,
    principal: Mapping[str, str],
    purpose: str,
    id_getter: Callable[[Any], str],
    version_getter: Callable[[Any], str | None] | None,
    keys: Sequence[str],
    session_id: str | None,
    data: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    out = dict(data)
    blocked_info: list[dict[str, Any]] = []
    for key in keys:
        items = out.get(key)
        if not isinstance(items, list) or not items:
            continue
        allowed, blocked = guard_retrieval(
            client, principal, purpose, items, id_getter, version_getter=version_getter, session_id=session_id
        )
        out[key] = allowed
        blocked_info += [
            {"key": key, "context_id": b.context_id, "decision": b.decision, "reasons": b.reasons}
            for b in blocked
        ]
    return out, blocked_info


def guard_node(
    client: InvariantClient,
    principal: Mapping[str, str],
    purpose: str,
    id_getter: Callable[[Any], str],
    *,
    version_getter: Callable[[Any], str | None] | None = None,
    keys: Sequence[str] = DEFAULT_KEYS,
    phase: str = "output",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    if phase not in ("input", "output", "both"):
        raise ValueError("phase must be 'input', 'output' or 'both'")

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        def pre(state: Mapping[str, Any]) -> tuple[Mapping[str, Any], list[dict[str, Any]]]:
            if phase == "output":
                return state, []
            return _filter_keys(
                client, principal, purpose, id_getter, version_getter, keys, state.get("session_id"), state
            )

        def post(state: Mapping[str, Any], result: Any, blocked: list[dict[str, Any]]) -> Any:
            if phase != "input" and isinstance(result, Mapping):
                result, more = _filter_keys(
                    client, principal, purpose, id_getter, version_getter, keys, state.get("session_id"), result
                )
                blocked = blocked + more
            if blocked and isinstance(result, Mapping):
                result = {**result, "ales_blocked": blocked}
            return result

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def awrapper(state: Mapping[str, Any], *a: Any, **kw: Any) -> Any:
                st, blocked = pre(state)
                return post(state, await fn(st, *a, **kw), blocked)

            return awrapper

        @functools.wraps(fn)
        def wrapper(state: Mapping[str, Any], *a: Any, **kw: Any) -> Any:
            st, blocked = pre(state)
            return post(state, fn(st, *a, **kw), blocked)

        return wrapper

    return decorator


def register_output(
    client: InvariantClient,
    parents_key: str,
    kind: str = "summary",
    *,
    text_key: str = "text",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register the node's text output as a derivative of the envelopes in ``state[parents_key]``."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        def register(state: Mapping[str, Any], result: Any) -> Any:
            text = result if isinstance(result, str) else (result or {}).get(text_key)
            parents = state.get(parents_key) or []
            if not isinstance(text, str) or not parents:
                return result
            env = new_derivative(
                kind, parents, client.tenant_id, f"{kind}:{text[:40]}", text, source_system="langgraph-node"
            )
            client.register_derivation(env)
            if isinstance(result, Mapping):
                return {
                    **result,
                    "ales_context_id": env["context_id"],
                    "ales_object_version": env["object_version"],
                }
            return result

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def awrapper(state: Mapping[str, Any], *a: Any, **kw: Any) -> Any:
                return register(state, await fn(state, *a, **kw))

            return awrapper

        @functools.wraps(fn)
        def wrapper(state: Mapping[str, Any], *a: Any, **kw: Any) -> Any:
            return register(state, fn(state, *a, **kw))

        return wrapper

    return decorator
