import json
from types import SimpleNamespace

import pytest
from ales_adapters import (
    CarrierError,
    ContextReference,
    DictRedis,
    GuardedCache,
    GuardedVectorStore,
    InMemoryVectorBackend,
    manifest_json,
    manifest_report,
)
from ales_adapters.langgraph_middleware import register_output
from ales_adapters.llamaindex_adapter import IngestionCallback
from ales_sdk import new_source


def _ref(**kw):
    base = {"tenant_id": "t1", "context_id": "c1", "object_version": "2", "content_digest": "sha256:x"}
    return ContextReference(**{**base, **kw})


def test_metadata_roundtrip_and_keys():
    r = _ref(authority_ref="auth-1", source_connector="s3")
    md = r.to_metadata()
    assert md == {
        "ales_context_id": "c1",
        "ales_version": "2",
        "ales_tenant": "t1",
        "ales_digest": "sha256:x",
        "ales_authority_ref": "auth-1",
        "ales_connector": "s3",
    }
    assert ContextReference.from_metadata(md) == r
    assert set(_ref().to_metadata()) == {"ales_context_id", "ales_version", "ales_tenant", "ales_digest"}


def test_from_metadata_tolerant_and_strict():
    assert ContextReference.from_metadata(None) is None
    assert ContextReference.from_metadata({}) is None
    assert ContextReference.from_metadata({"ales_digest": "d", "other": 1}) is None
    legacy = ContextReference.from_metadata({"ales_context_id": "c", "ales_version": "1"})
    assert legacy and legacy.tenant_id == "" and legacy.content_digest == ""
    for bad in (
        {"ales_context_id": "c"},
        {"ales_version": "1"},
        {"ales_tenant": "t"},
        {"ales_context_id": 5, "ales_version": "1"},
        {"ales_context_id": "c", "ales_version": "1", "ales_digest": 3},
        {"ales_context_id": "", "ales_version": "1"},
    ):
        with pytest.raises(CarrierError):
            ContextReference.from_metadata(bad)


def test_llamaindex_stamp_is_byte_compatible_superset(client, src):
    node = SimpleNamespace(
        metadata={},
        excluded_embed_metadata_keys=[],
        excluded_llm_metadata_keys=[],
        node_id="n1",
        get_content=lambda: "chunk",
    )
    (out,) = IngestionCallback(client)(src, [node])
    # today's keys, unchanged values
    assert out.metadata["ales_context_id"] and out.metadata["ales_version"] == "1"
    # carrier fields present and consistent
    ref = ContextReference.from_metadata(out.metadata)
    assert ref and ref.tenant_id == client.tenant_id and ref.content_digest
    assert {"ales_context_id", "ales_version"} <= set(out.excluded_embed_metadata_keys)
    assert set(out.metadata) <= set(out.excluded_llm_metadata_keys)


def test_langgraph_update_keys_unchanged(client, src):
    @register_output(client, parents_key="documents")
    def node(state):
        return {"text": "summary text"}

    out = node({"documents": [src]})
    assert set(out) == {"text", "ales_context_id", "ales_object_version"}
    assert out["ales_object_version"] == "1"


def test_redis_record_and_vector_payload_wire_format_unchanged(client, src):
    r = DictRedis()
    env = GuardedCache(client, {"type": "user", "id": "a"}, "p", r).put("k", {"v": 1}, [src])
    rec = json.loads(r.get("k"))
    assert rec == {"value": {"v": 1}, "context_id": env["context_id"], "version": env["object_version"]}
    assert list(rec) == ["value", "context_id", "version"]

    backend = InMemoryVectorBackend()
    store = GuardedVectorStore(client, {"type": "user", "id": "a"}, "p", backend)
    env2 = store.add_derived(
        [src], "hello", [1.0, 0.0, 0.0], payload={"classification": "internal", "version": "bogus"}
    )
    ((_, _, payload),) = backend.search([1.0, 0.0, 0.0], 1)
    assert payload == {
        "classification": "internal",
        "text": "hello",
        "context_id": env2["context_id"],
        "version": env2["object_version"],
    }


def test_payload_forms():
    r = _ref()
    assert r.to_payload() == {"context_id": "c1", "version": "2"}
    assert r.to_state_update() == {"ales_context_id": "c1", "ales_object_version": "2"}
    assert ContextReference.from_payload(r.to_payload()).context_id == "c1"
    assert ContextReference.from_payload({}) is None
    with pytest.raises(CarrierError):
        ContextReference.from_payload({"context_id": "c"})


def test_from_envelope():
    env = new_source("t1", "o", "body", "sys")
    r = ContextReference.from_envelope(env)
    assert (r.tenant_id, r.context_id, r.object_version, r.content_digest) == (
        "t1",
        env["context_id"],
        env["object_version"],
        env["content_digest"],
    )


def test_manifests_complete_and_honest():
    ms = {m.adapter: m for m in manifest_report()}
    assert {
        "fs_source",
        "s3_connector",
        "azure_blob_connector",
        "webhook_connector",
        "vector_store_inmemory",
        "pgvector_portable",
        "pgvector_native",
        "qdrant",
        "redis_cache",
        "langgraph_middleware",
        "llamaindex",
        "acs",
        "model_gateway",
    } <= set(ms)
    assert ms["langgraph_middleware"].tested_upstream_versions == {"langgraph": "not-imported"}
    assert ms["llamaindex"].tested_upstream_versions["llama-index-core"] == ">=0.11"
    assert ms["llamaindex"].tool_egress_interception == "unsupported"
    assert ms["acs"].session_reset.startswith("supported")
    assert (
        ms["fs_source"].retrieval_interception == "n/a"
        and ms["fs_source"].enforcement_level == "INGESTION_ONLY"
    )
    assert ms["s3_connector"].parent_preservation == "unsupported"
    for m in ms.values():
        assert m.parent_preservation == "unsupported" or m.parent_preservation.startswith("supported: ")
    data = json.loads(manifest_json())
    assert len(data) == len(ms) and all("tested_upstream_versions" in d for d in data)
