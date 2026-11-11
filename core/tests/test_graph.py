from __future__ import annotations

import pytest
from ales_core import AuthorityWidening, GraphStore, InvalidEnvelope, LineageIncomplete
from core_fixtures import make_env


def key(env):
    return (env.context_id, env.object_version)


def test_ancestors_chain(graph, chain):
    anc = graph.get_ancestors("tenant-a", chain["memory"].context_id, "v1")
    assert set(anc) == {key(chain["summary"]), key(chain["chunk"]), key(chain["source"])}
    assert graph.get_ancestors("tenant-a", chain["source"].context_id, "v1") == []


def test_descendants_chain(graph, chain):
    desc = graph.get_descendants("tenant-a", chain["source"].context_id, "v1")
    assert set(desc) == {key(chain["chunk"]), key(chain["summary"]), key(chain["memory"])}
    assert graph.get_descendants("tenant-a", chain["memory"].context_id, "v1") == []
    # version=None starts from all versions
    assert set(graph.get_descendants("tenant-a", chain["source"].context_id)) == set(desc)


def test_diamond_dedupes(graph, session):
    s = make_env("source")
    a = make_env("chunk", [(s.context_id, "v1")])
    b = make_env("chunk", [(s.context_id, "v1")])
    j = make_env("summary", [(a.context_id, "v1"), (b.context_id, "v1")])
    graph.register_source(s)
    for e in (a, b, j):
        graph.register_derivation(e)
    assert len(graph.get_ancestors("tenant-a", j.context_id, "v1")) == 3
    assert len(graph.get_descendants("tenant-a", s.context_id, "v1")) == 3


def test_tenant_isolation(graph, chain):
    assert graph.get_ancestors("tenant-b", chain["memory"].context_id, "v1") == []
    assert graph.get_descendants("tenant-b", chain["source"].context_id, "v1") == []
    assert graph.get_object("tenant-b", chain["source"].context_id, "v1") is None
    assert graph.get_versions("tenant-b", chain["source"].context_id) == []


def test_cross_tenant_parent_is_missing(graph, chain):
    child = make_env("chunk", [(chain["source"].context_id, "v1")], tenant="tenant-b")
    with pytest.raises(LineageIncomplete):
        graph.register_derivation(child)


def test_lineage_incomplete_on_missing_parent(graph, chain):
    ghost = make_env("source")
    child = make_env("chunk", [(chain["source"].context_id, "v1"), (ghost.context_id, "v1")])
    with pytest.raises(LineageIncomplete) as ei:
        graph.register_derivation(child)
    assert ei.value.missing == [(ghost.context_id, "v1")]


def test_missing_parent_version_is_incomplete(graph, chain):
    child = make_env("chunk", [(chain["source"].context_id, "v99")])
    with pytest.raises(LineageIncomplete):
        graph.register_derivation(child)


def test_registration_refuses_wider_derivative(graph):
    s = make_env("source", classification="confidential", principals=["alice"])
    graph.register_source(s)
    with pytest.raises(AuthorityWidening):
        graph.register_derivation(
            make_env("chunk", [(s.context_id, "v1")], classification="public", principals=["alice"])
        )
    with pytest.raises(AuthorityWidening):
        graph.register_derivation(make_env("chunk", [(s.context_id, "v1")], classification="confidential"))
    graph.register_derivation(
        make_env("chunk", [(s.context_id, "v1")], classification="restricted", principals=["alice"])
    )


def test_kind_validation(graph):
    with pytest.raises(InvalidEnvelope):
        graph.register_source(make_env("source").model_copy(update={"kind": "chunk"}))


def test_register_idempotent(graph):
    s = make_env("source")
    r1 = graph.register_source(s)
    r2 = graph.register_source(s)
    assert r1 is r2


def test_graphstore_type(graph):
    assert isinstance(graph, GraphStore)
