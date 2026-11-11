import pytest
from ales_adapters.pgvector_store import GuardedVectorStore, InMemoryVectorBackend, PgVectorBackend
from ales_sdk import new_source
from conftest import PRINCIPAL


def _backend(kind, tmp_path):
    if kind == "memory":
        return InMemoryVectorBackend()
    sa = pytest.importorskip("sqlalchemy")
    return PgVectorBackend(sa.create_engine(f"sqlite:///{tmp_path / 'v.db'}"))


@pytest.mark.parametrize("kind", ["memory", "sql"])
def test_add_search_allow_then_revoke_excludes(client, src, server, tmp_path, kind):
    store = GuardedVectorStore(client, PRINCIPAL, "support", _backend(kind, tmp_path))
    far = store.add_derived([src], "far away", [0.0, 1.0])
    near = store.add_derived([src], "near", [1.0, 0.1])
    assert near["parent_refs"][0]["context_id"] == src["context_id"]
    assert near["kind"] == "chunk" and near["context_id"] in server.envelopes

    allowed, blocked = store.search([1.0, 0.0], k=5, session_id="s1")
    assert [h.context_id for h in allowed] == [near["context_id"], far["context_id"]]
    assert allowed[0].payload["text"] == "near" and blocked == []
    assert client.session_taint.contexts_for("s1") == {near["context_id"], far["context_id"]}

    client.submit_revocation({"source_id": src["context_id"], "reason": "deleted"})
    allowed, blocked = store.search([1.0, 0.0], k=5)
    assert allowed == []
    assert {b.context_id for b in blocked} == {near["context_id"], far["context_id"]}
    assert blocked[0].decision == "DENY" and "ANCESTOR_ACL_REVOKED" in blocked[0].reasons


def test_only_revoked_parent_chunks_blocked(client, src):
    other_src = new_source("t1", "doc-2", "x", "test")
    client.register_source(other_src)
    store = GuardedVectorStore(client, PRINCIPAL, "support", InMemoryVectorBackend())
    a = store.add_derived([src], "a", [1.0, 0.0])
    b = store.add_derived([other_src], "b", [1.0, 0.0])
    client.submit_revocation({"source_id": src["context_id"], "reason": "deleted"})
    allowed, blocked = store.search([1.0, 0.0])
    assert [h.context_id for h in allowed] == [b["context_id"]]
    assert [x.context_id for x in blocked] == [a["context_id"]]
