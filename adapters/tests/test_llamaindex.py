import asyncio

import pytest
from adapters_fixtures import PRINCIPAL
from ales_adapters.llamaindex_adapter import GuardedLlamaRetriever, IngestionCallback
from ales_sdk import new_source


class FakeNode:
    def __init__(self, node_id, text, metadata=None):
        self.node_id = node_id
        self._text = text
        self.metadata = dict(metadata or {})
        self.excluded_embed_metadata_keys = []
        self.excluded_llm_metadata_keys = []

    def get_content(self):
        return self._text


class FakeNWS:
    def __init__(self, node):
        self.node, self.score = node, 0.5


class FakeRetriever:
    def __init__(self, nodes):
        self.nodes = nodes

    def retrieve(self, query):
        return [FakeNWS(n) for n in self.nodes]

    async def aretrieve(self, query):
        return self.retrieve(query)


def _ingest(client, n=2):
    srcs = [new_source("t1", f"d{i}", f"c{i}", "test") for i in range(n)]
    nodes = []
    for i, s in enumerate(srcs):
        client.register_source(s)
        node = FakeNode(f"n{i}", f"text {i}")
        IngestionCallback(client)(s, [node])
        nodes.append(node)
    return srcs, nodes


def test_ingestion_stamps_metadata_and_registers_with_parents(client, server):
    src = new_source("t1", "doc", "body", "test")
    client.register_source(src)
    nodes = [FakeNode("a", "alpha"), FakeNode("b", "beta")]
    out = IngestionCallback(client)(src, nodes)
    assert out == nodes
    for n in nodes:
        assert n.metadata["ales_context_id"] and n.metadata["ales_version"] == "1"
        assert {"ales_context_id", "ales_version"} <= set(n.excluded_embed_metadata_keys)
        assert {"ales_context_id", "ales_version"} <= set(n.excluded_llm_metadata_keys)
    assert nodes[0].metadata["ales_context_id"] != nodes[1].metadata["ales_context_id"]
    # lineage: revoking the parent denies the registered chunks
    client.submit_revocation({"source_id": src["context_id"], "reason": "deleted"})
    r = client.authorize(PRINCIPAL, "p", [(n.metadata["ales_context_id"], "1") for n in nodes])
    assert all(r.verdict_for(n.metadata["ales_context_id"]).decision == "DENY" for n in nodes)


def test_ingestion_per_node_parents_and_bind(client):
    s0, s1 = (new_source("t1", f"d{i}", "c", "test") for i in range(2))
    for s in (s0, s1):
        client.register_source(s)
    nodes = [FakeNode("a", "x"), FakeNode("b", "y")]
    IngestionCallback(client).bind(lambda n: s0 if n.node_id == "a" else [s1])(nodes)
    client.submit_revocation({"source_id": s1["context_id"], "reason": "deleted"})
    g = GuardedLlamaRetriever(client, PRINCIPAL, "p", FakeRetriever(nodes))
    allowed, blocked = g.retrieve("q")
    assert [n.node.node_id for n in allowed] == ["a"] and blocked[0].context_id == nodes[1].metadata[
        "ales_context_id"
    ]


def test_ingestion_requires_parents(client):
    with pytest.raises(ValueError):
        IngestionCallback(client)([], [FakeNode("a", "x")])


def test_retrieval_filters_revoked_and_taints_session(client):
    srcs, nodes = _ingest(client)
    client.submit_revocation({"source_id": srcs[0]["context_id"], "reason": "deleted"})
    g = GuardedLlamaRetriever(client, PRINCIPAL, "support", FakeRetriever(nodes), session_id="s1")
    allowed, blocked = g.retrieve("q")
    assert [n.node for n in allowed] == [nodes[1]]
    assert blocked[0].decision == "DENY" and blocked[0].item.node is nodes[0]
    assert client.session_taint.contexts_for("s1") == {nodes[1].metadata["ales_context_id"]}
    allowed, _ = asyncio.run(g.aretrieve("q"))
    assert [n.node for n in allowed] == [nodes[1]]


def test_order_preserved_with_mixed_nodes(client):
    srcs, nodes = _ingest(client, 3)
    client.submit_revocation({"source_id": srcs[1]["context_id"], "reason": "deleted"})
    allowed, blocked = GuardedLlamaRetriever(client, PRINCIPAL, "p", FakeRetriever(nodes)).retrieve("q")
    assert [n.node.node_id for n in allowed] == ["n0", "n2"] and len(blocked) == 1


def test_unregistered_deny_is_default(client):
    _, nodes = _ingest(client, 1)
    stray = FakeNode("stray", "no stamp")
    allowed, blocked = GuardedLlamaRetriever(
        client, PRINCIPAL, "p", FakeRetriever([nodes[0], stray])
    ).retrieve("q")
    assert [n.node for n in allowed] == [nodes[0]]
    assert blocked[0].reasons == ["UNREGISTERED_NODE"] and blocked[0].item.node is stray


def test_unregistered_allow(client):
    _, nodes = _ingest(client, 1)
    stray = FakeNode("stray", "no stamp")
    g = GuardedLlamaRetriever(
        client, PRINCIPAL, "p", FakeRetriever([stray, nodes[0]]), unregistered="allow", session_id="s"
    )
    allowed, blocked = g.retrieve("q")
    assert [n.node for n in allowed] == [stray, nodes[0]] and blocked == []
    assert "ales_context_id" not in stray.metadata
    assert client.session_taint.contexts_for("s") == {nodes[0].metadata["ales_context_id"]}


def test_unregistered_register_then_revocable(client):
    stray = FakeNode("stray", "no stamp")
    g = GuardedLlamaRetriever(client, PRINCIPAL, "p", FakeRetriever([stray]), unregistered="register")
    allowed, blocked = g.retrieve("q")
    assert len(allowed) == 1 and blocked == []
    cid = stray.metadata["ales_context_id"]
    client.submit_revocation({"source_id": cid, "reason": "deleted"})
    allowed, blocked = g.retrieve(
        "q"
    )  # now stamped, so it is authorized (and denied) rather than re-registered
    assert allowed == [] and blocked[0].context_id == cid and blocked[0].decision == "DENY"


def test_malformed_stamp_blocked_under_every_policy(client):
    bad = FakeNode("bad", "x", {"ales_context_id": 123})
    for policy in ("deny", "allow", "register"):
        allowed, blocked = GuardedLlamaRetriever(
            client, PRINCIPAL, "p", FakeRetriever([bad]), unregistered=policy
        ).retrieve("q")
        assert allowed == [] and blocked[0].reasons == ["ALES_METADATA_MALFORMED"]


def test_unknown_stamped_node_blocked_and_bad_policy(client):
    ghost = FakeNode("g", "x", {"ales_context_id": "does-not-exist", "ales_version": "1"})
    allowed, blocked = GuardedLlamaRetriever(client, PRINCIPAL, "p", FakeRetriever([ghost])).retrieve("q")
    assert allowed == [] and blocked[0].decision == "UNKNOWN"
    with pytest.raises(ValueError):
        GuardedLlamaRetriever(client, PRINCIPAL, "p", FakeRetriever([]), unregistered="maybe")


def test_bare_nodes_without_wrapper_and_empty_results(client):
    _, nodes = _ingest(client, 1)

    class BareRetriever:
        def retrieve(self, q):
            return list(nodes)

    allowed, _ = GuardedLlamaRetriever(client, PRINCIPAL, "p", BareRetriever()).retrieve("q")
    assert allowed == nodes
    assert GuardedLlamaRetriever(client, PRINCIPAL, "p", FakeRetriever([])).retrieve("q") == ([], [])


llama = pytest.importorskip("llama_index.core", reason="llama-index-core not installed")


def test_real_llamaindex_vector_index_roundtrip(client):
    from llama_index.core import VectorStoreIndex
    from llama_index.core.embeddings import MockEmbedding
    from llama_index.core.schema import TextNode

    srcs = [new_source("t1", f"real{i}", f"c{i}", "test") for i in range(2)]
    nodes = []
    for i, s in enumerate(srcs):
        client.register_source(s)
        n = TextNode(text=f"real text {i}", id_=f"real-{i}")
        IngestionCallback(client)(s, [n])
        nodes.append(n)
    assert "ales_context_id" in nodes[0].excluded_embed_metadata_keys
    index = VectorStoreIndex(nodes, embed_model=MockEmbedding(embed_dim=8))
    g = GuardedLlamaRetriever(client, PRINCIPAL, "p", index.as_retriever(similarity_top_k=5))
    allowed, blocked = g.retrieve("real text")
    assert {n.node.node_id for n in allowed} == {"real-0", "real-1"} and blocked == []

    client.submit_revocation({"source_id": srcs[0]["context_id"], "reason": "deleted"})
    allowed, blocked = g.retrieve("real text")
    assert [n.node.node_id for n in allowed] == ["real-1"]
    assert blocked[0].item.node.node_id == "real-0" and blocked[0].decision == "DENY"

    stray = VectorStoreIndex([TextNode(text="stray", id_="stray")], embed_model=MockEmbedding(embed_dim=8))
    allowed, blocked = GuardedLlamaRetriever(client, PRINCIPAL, "p", stray.as_retriever()).retrieve("stray")
    assert allowed == [] and blocked[0].reasons == ["UNREGISTERED_NODE"]
