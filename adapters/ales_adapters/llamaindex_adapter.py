"""LlamaIndex integration (no hard dependency: ``llama_index`` is never imported by this module).

Everything is duck-typed against the two LlamaIndex shapes it touches:

* a retriever: ``retrieve(query) -> list[NodeWithScore]`` (async: ``aretrieve``);
* a ``NodeWithScore``-like result: ``.node`` with a ``.metadata`` dict and ``.get_content()``
  (a bare node without the ``.node`` wrapper is accepted too).

Ingestion::

    cb = IngestionCallback(client)
    nodes = splitter.get_nodes_from_documents(docs)
    cb(source_envelope, nodes)          # registers each chunk as a derivative; stamps metadata
    index = VectorStoreIndex(nodes, ...)

Each node gets ``metadata["ales_context_id"]`` / ``metadata["ales_version"]`` (and the keys are added to the
node's ``excluded_embed_metadata_keys`` / ``excluded_llm_metadata_keys`` when present so they do not leak
into embeddings or prompts). Retrieval::

    guarded = GuardedLlamaRetriever(client, principal, "support", index.as_retriever(), session_id="s1")
    allowed_nodes, blocked = guarded.retrieve("question")

Unregistered nodes (no ``ales_context_id``) follow ``unregistered=``:

* ``"deny"`` (default, and the only choice appropriate for a protected deployment): the node is blocked
  with reason ``UNREGISTERED_NODE``. Unknown provenance cannot be revoked, so it must not be served.
* ``"allow"``: pass through untouched and UNTRACKED (no session taint, no revocation). Use only for
  indexes that deliberately mix in non-governed content.
* ``"register"``: register the node on the fly as a *source* envelope (``register_kwargs`` sets
  classification / scopes; default classification ``internal``) and then authorize it like any other.
  This asserts the node is a legitimate root; it grants nothing the registered scopes do not allow.

A node whose ALES stamp is malformed (non-string ids) is always blocked (``ALES_METADATA_MALFORMED``),
whatever the policy: a damaged stamp is not the same as no stamp.

Coverage: only reads made through ``GuardedLlamaRetriever`` are enforced; querying the index's vector
store or docstore directly is uninstrumented.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ales_sdk.client import InvariantClient
from ales_sdk.envelope import new_derivative, new_source
from ales_sdk.wrappers import Blocked, guard_retrieval

from .carrier import META_CONTEXT_ID, META_VERSION, ContextReference, stamp_node_metadata

UNREGISTERED_POLICIES = ("deny", "allow", "register")
UNREGISTERED_REASON = "UNREGISTERED_NODE"
MALFORMED_REASON = "ALES_METADATA_MALFORMED"


def _inner(item: Any) -> Any:
    return getattr(item, "node", item)


def _metadata(item: Any) -> Mapping[str, Any]:
    md = getattr(_inner(item), "metadata", None)
    return md if isinstance(md, Mapping) else {}


def _content(item: Any) -> str:
    return str(_inner(item).get_content())


def _node_id(item: Any) -> str:
    n = _inner(item)
    return str(getattr(n, "node_id", None) or getattr(n, "id_", None) or uuid.uuid4())


def _stamp(node: Any, env: Mapping[str, Any]) -> None:
    stamp_node_metadata(node, ContextReference.from_envelope(env))


class IngestionCallback:
    """Register LlamaIndex nodes as chunk derivatives of their parent source envelope(s).

    ``parents`` is a source/derivative envelope, a sequence of them (shared by every node), or a callable
    ``node -> envelope(s)`` for per-node lineage. Returns the same nodes, stamped.
    """

    def __init__(self, client: InvariantClient, kind: str = "chunk", source_system: str = "llamaindex") -> None:
        self.client = client
        self.kind = kind
        self.source_system = source_system

    def __call__(self, parents: Any, nodes: Sequence[Any]) -> list[Any]:
        out = list(nodes)
        for item in out:
            node = _inner(item)
            p = parents(node) if callable(parents) else parents
            plist = [p] if isinstance(p, Mapping) else list(p)
            if not plist:
                raise ValueError("every node needs at least one parent envelope")
            env = new_derivative(
                self.kind,
                plist,
                self.client.tenant_id,
                _node_id(node),
                _content(node),
                source_system=self.source_system,
            )
            self.client.register_derivation(env)
            _stamp(node, env)
        return out

    def bind(self, parents: Any) -> Callable[[Sequence[Any]], list[Any]]:
        """``nodes -> nodes`` transformation for an ingestion pipeline."""
        return lambda nodes: self(parents, nodes)


class GuardedLlamaRetriever:
    """Wrap a retriever so only nodes the principal may use *now* are returned."""

    def __init__(
        self,
        client: InvariantClient,
        principal: Mapping[str, str],
        purpose: str,
        retriever: Any,
        *,
        unregistered: str = "deny",
        session_id: str | None = None,
        agent_id: str | None = None,
        register_kwargs: Mapping[str, Any] | None = None,
    ) -> None:
        if unregistered not in UNREGISTERED_POLICIES:
            raise ValueError(f"unregistered must be one of {UNREGISTERED_POLICIES}, got {unregistered!r}")
        self.client = client
        self.principal = dict(principal)
        self.purpose = purpose
        self.retriever = retriever
        self.unregistered = unregistered
        self.session_id = session_id
        self.agent_id = agent_id
        self.register_kwargs = dict(register_kwargs or {})

    def retrieve(self, query: Any) -> tuple[list[Any], list[Blocked]]:
        return self.filter(self.retriever.retrieve(query))

    async def aretrieve(self, query: Any) -> tuple[list[Any], list[Blocked]]:
        return self.filter(await self.retriever.aretrieve(query))

    def filter(self, nodes: Sequence[Any]) -> tuple[list[Any], list[Blocked]]:
        """Filter already-retrieved nodes; order of the allowed nodes is preserved."""
        slots: list[tuple[Any, str | None, str | None]] = []  # (node, context_id, version) in order
        blocked_early: dict[int, Blocked] = {}
        for i, item in enumerate(nodes):
            md = _metadata(item)
            cid, ver = md.get(META_CONTEXT_ID), md.get(META_VERSION)
            if cid is None:
                if self.unregistered == "allow":
                    slots.append((item, None, None))
                elif self.unregistered == "register":
                    cid, ver = self._register(item)
                    slots.append((item, cid, ver))
                else:
                    blocked_early[i] = Blocked(item, "", "DENY", [UNREGISTERED_REASON])
                    slots.append((item, None, None))
            elif not isinstance(cid, str) or not cid or not (ver is None or isinstance(ver, str)):
                blocked_early[i] = Blocked(item, str(cid), "DENY", [MALFORMED_REASON])
                slots.append((item, None, None))
            else:
                slots.append((item, cid, ver))

        guarded = [s for i, s in enumerate(slots) if s[1] is not None and i not in blocked_early]
        allowed_ids: set[int] = set()
        blocked_by_id: dict[int, Blocked] = {}
        if guarded:
            ok, bad = guard_retrieval(
                self.client,
                self.principal,
                self.purpose,
                guarded,
                lambda s: s[1] or "",
                version_getter=lambda s: s[2],
                agent_id=self.agent_id,
                session_id=self.session_id,
            )
            allowed_ids = {id(s) for s in ok}
            for b in bad:
                blocked_by_id[id(b.item)] = Blocked(
                    b.item[0], b.context_id, b.decision, b.reasons, b.needs_override
                )

        allowed: list[Any] = []
        blocked: list[Blocked] = []
        for i, s in enumerate(slots):
            if i in blocked_early:
                blocked.append(blocked_early[i])
            elif s[1] is None or id(s) in allowed_ids:  # unregistered + "allow"
                allowed.append(s[0])
            else:
                blocked.append(blocked_by_id[id(s)])
        return allowed, blocked

    def _register(self, item: Any) -> tuple[str, str]:
        node = _inner(item)
        env = new_source(
            self.client.tenant_id,
            _node_id(node),
            _content(node),
            "llamaindex-unregistered",
            **self.register_kwargs,
        )
        self.client.register_source(env)
        if isinstance(getattr(node, "metadata", None), dict):
            _stamp(node, env)
        return env["context_id"], env["object_version"]
