"""Per-adapter coverage declaration (spec: OBSERVE_ONLY adapters are excluded from coverage claims)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

ADAPTER_COVERAGE: dict[str, dict[str, Any]] = {
    "fs_source": {
        "enters": "Every file under the root directory is registered as a source envelope.",
        "derives": "Nothing; it only creates sources.",
        "retrieves": "n/a (ingestion and event emission only).",
        "can_block": "n/a (emits revocation events on delete, content change and ACL narrowing).",
        "enforcement": "ENFORCING",
        "notes": "Ingestion and event-only: blocking happens in the downstream adapters consuming these sources.",
    },
    "pgvector_store": {
        "enters": "Chunk/embedding derivatives registered through add_derived().",
        "derives": "Chunk envelopes with parent lineage from the source envelopes.",
        "retrieves": "search() results are filtered through guard_retrieval before being returned.",
        "can_block": "Yes: revoked/denied/unknown hits are never returned.",
        "enforcement": "ENFORCING",
        "notes": "Portable fallback (JSON vectors, Python-side cosine; not the pgvector extension, see pgvector_native). Only covers reads made through GuardedVectorStore; direct backend access is uninstrumented.",
    },
    "qdrant": {
        "enters": "Chunk/embedding derivatives registered through add_derived() into a Qdrant collection.",
        "derives": "Chunk envelopes with parent lineage from the source envelopes.",
        "retrieves": "search() results are filtered through guard_retrieval before being returned.",
        "can_block": "Yes: revoked/denied/unknown hits are never returned; VectorPurgeTarget physically deletes the point (version-aware).",
        "enforcement": "ENFORCING",
        "notes": "Verified against a live Qdrant. Direct Qdrant client access bypassing GuardedVectorStore is uninstrumented.",
    },
    "pgvector_native": {
        "enters": "Chunk/embedding derivatives registered through add_derived() into a pgvector vector(n) table.",
        "derives": "Chunk envelopes with parent lineage from the source envelopes.",
        "retrieves": "search() ranks with the pgvector <=> operator in Postgres, then filters through guard_retrieval.",
        "can_block": "Yes: revoked/denied/unknown hits are never returned; VectorPurgeTarget physically deletes the row (atomic version-aware DELETE).",
        "enforcement": "ENFORCING",
        "notes": "Real pgvector extension, verified against a live PostgreSQL. Direct SQL access bypassing GuardedVectorStore is uninstrumented.",
    },
    "redis_cache": {
        "enters": "Cache entries registered as cache-kind derivatives through put().",
        "derives": "Cache envelopes with parent lineage from the envelopes the value was built from.",
        "retrieves": "get() authorizes the entry's context before returning a value.",
        "can_block": "Yes: blocked entries return None and the stale entry is deleted best-effort.",
        "enforcement": "ENFORCING",
        "notes": "Verified against DictRedis and a live Redis (redis-py). Direct redis access bypassing GuardedCache is uninstrumented.",
    },
    "langgraph_middleware": {
        "enters": "Node outputs registered as derivatives through register_output().",
        "derives": "Summary (or other kind) envelopes with parents taken from graph state.",
        "retrieves": "guard_node filters documents/results state keys through guard_retrieval.",
        "can_block": "Yes: blocked documents are removed from state before the next node sees them.",
        "enforcement": "ENFORCING",
        "notes": "Only wrapped nodes are covered; unwrapped nodes and tools are uninstrumented.",
    },
    "llamaindex": {
        "enters": "Nodes registered as chunk derivatives by IngestionCallback (metadata ales_context_id/ales_version stamped).",
        "derives": "Chunk envelopes with parent lineage from the source envelope(s) passed at ingestion.",
        "retrieves": "GuardedLlamaRetriever filters retrieve()/aretrieve() results through guard_retrieval.",
        "can_block": "Yes: revoked/denied/unknown nodes are never returned; unregistered nodes are denied by default (policy deny|allow|register).",
        "enforcement": "ENFORCING",
        "notes": "ENFORCING for the retrieval path only. Unmediated: direct vector-store/docstore access, query engines or synthesizers built on an unwrapped retriever, nodes ingested without IngestionCallback under unregistered='allow'. Duck-typed; llama_index is optional.",
    },
    "acs": {
        "enters": "after_memory_write registers memory derivatives (parents from ctx active_context_ids or session taint).",
        "derives": "Memory envelopes whose parents are the session's active context.",
        "retrieves": "after_knowledge_retrieval / before_memory_read filter through guard_retrieval / guard_memory_read.",
        "can_block": "Yes: blocked items are redacted; before_tool_call / before_message_send deny with required_action=session_reset when the session depends on revoked context.",
        "enforcement": "ENFORCING",
        "notes": "Targets ACS draft hook semantics, adapter contract v0. ENFORCING only for the hooks it mediates (before/after_knowledge_retrieval, before_memory_read, after_memory_write, before_tool_call, before_message_send).",
        "unmediated": [
            "direct store writes and reads that bypass the host runtime's hooks",
            "content of tool arguments and outgoing messages (only session dependence is checked, no DLP)",
            "hooks the host runtime does not invoke",
            "memory entries stored without the context_id returned by after_memory_write",
        ],
    },
}


# A precise alternative to "works with framework X": one record per adapter stating which interception
# points it mediates. Capability fields are "supported", "partial: <what is covered>", "unsupported" or
# "n/a" (the adapter has no such surface). Conformance (``ales_conformance.report``) cross-checks every
# retrieval_interception "supported" claim against a passing contract run; unproven claims render UNVERIFIED.


@dataclass(frozen=True)
class Manifest:
    adapter: str
    source_ingestion: str
    parent_preservation: str  # "supported: <transforms>" | "unsupported"
    retrieval_interception: str
    memory_interception: str
    model_context_interception: str
    tool_egress_interception: str
    physical_purge: str
    session_reset: str
    tested_upstream_versions: dict[str, str] = field(
        default_factory=dict
    )  # pkg -> PEP 440 range or "not-imported"
    enforcement_level: str = "ENFORCING"
    conformance_subject: str | None = (
        None  # prefix of the conformance report row that proves retrieval claims
    )
    exercised_versions: dict[str, str] = field(
        default_factory=dict
    )  # pkg -> version the tests actually ran against
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def claims_retrieval(self) -> bool:
        return self.retrieval_interception.startswith("supported")


_NA = "n/a"
_NO = "unsupported"
_TAINT = "partial: taint recorded via session_id; no reset signal"
_SRC_NOTE = "Creates source roots (no parents); blocking happens in downstream adapters."


def _connector_coverage(cls_name: str) -> str:
    """Event coverage of a connector, read (not modified) from ales_connectors; empty when not installed."""
    mods = {
        "S3Connector": "s3_source",
        "AzureBlobConnector": "azure_blob_source",
        "WebhookConnector": "webhook_source",
    }
    try:
        import importlib

        cov = getattr(importlib.import_module(f"ales_connectors.{mods[cls_name]}"), cls_name).coverage
        return ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in sorted(cov.items()))
    except Exception:  # noqa: BLE001 - optional package / optional extra
        return ""


def _gateway_constants() -> str:
    try:
        from ales_sdk import model_gateway as mg

        return f"id keys {mg.ID_KEY}/{mg.VERSION_KEY}; untracked modes {','.join(mg._UNTRACKED_MODES)}."
    except Exception:  # noqa: BLE001
        return ""


def _source(
    name: str, extra: str, versions: dict[str, str] | None = None, subject: str | None = None
) -> Manifest:
    return Manifest(
        adapter=name,
        source_ingestion="supported",
        parent_preservation=_NO,
        retrieval_interception=_NA,
        memory_interception=_NA,
        model_context_interception=_NA,
        tool_egress_interception=_NA,
        physical_purge=_NA,
        session_reset=_NA,
        tested_upstream_versions=versions or {},
        enforcement_level="INGESTION_ONLY",
        conformance_subject=subject,
        notes=f"{_SRC_NOTE} {extra}".strip(),
    )


def _store(
    name: str, versions: dict[str, str], exercised: dict[str, str], subject: str | None, notes: str
) -> Manifest:
    return Manifest(
        adapter=name,
        source_ingestion=_NO,
        parent_preservation="supported: chunk, embedding (parents via add_derived)",
        retrieval_interception="supported",
        memory_interception=_NO,
        model_context_interception=_NO,
        tool_egress_interception=_NO,
        physical_purge="supported",
        session_reset=_TAINT,
        tested_upstream_versions=versions,
        enforcement_level="ENFORCING",
        conformance_subject=subject,
        exercised_versions=exercised,
        notes=notes,
    )


def manifest_report() -> list[Manifest]:
    s3, az, wh = (_connector_coverage(n) for n in ("S3Connector", "AzureBlobConnector", "WebhookConnector"))
    absent = "ales_connectors not installed"
    return [
        _source(
            "fs_source", "Events: deleted, version_superseded, acl_changed (all yes).", subject="fs_source"
        ),
        _source(
            "s3_connector",
            f"Event coverage: {s3 or absent}. Native S3 ACL changes are not observed.",
            {"boto3": ">=1.34"},
        ),
        _source(
            "azure_blob_connector",
            f"Event coverage: {az or absent}. Native Azure RBAC changes are not observed.",
            {"azure-storage-blob": ">=12.19"},
        ),
        _source(
            "webhook_connector",
            f"Event coverage: {wh or absent}. Push-based; completeness depends on the sender.",
        ),
        _store(
            "vector_store_inmemory",
            {},
            {},
            "GuardedVectorStore (InMemory backend)",
            "Process-local stand-in backend.",
        ),
        _store(
            "pgvector_portable",
            {"sqlalchemy": ">=2.0"},
            {},
            None,
            "JSON vectors + Python-side cosine over SQLAlchemy; no dedicated conformance row, so retrieval is UNVERIFIED.",
        ),
        _store(
            "pgvector_native",
            {"pgvector": ">=0.3"},
            {},
            "GuardedVectorStore (pgvector native, live)",
            "Verified only when a live PostgreSQL+pgvector was reachable at report generation.",
        ),
        _store(
            "qdrant",
            {"qdrant-client": ">=1.9"},
            {"qdrant-client": "1.20.0"},
            "GuardedVectorStore (Qdrant, live)",
            "Verified only when a live Qdrant was reachable at report generation.",
        ),
        Manifest(
            adapter="redis_cache",
            source_ingestion=_NO,
            parent_preservation="supported: cache",
            retrieval_interception="supported",
            memory_interception=_NO,
            model_context_interception=_NO,
            tool_egress_interception=_NO,
            physical_purge="supported",
            session_reset=_TAINT,
            tested_upstream_versions={"redis": ">=5.0"},
            enforcement_level="ENFORCING",
            conformance_subject="GuardedCache (DictRedis)",
            exercised_versions={"redis": "8.1.0"},
            notes="Cache read path only; direct redis access is uninstrumented.",
        ),
        Manifest(
            adapter="langgraph_middleware",
            source_ingestion=_NO,
            parent_preservation="supported: summary / any node output (parents from a state key)",
            retrieval_interception="supported",
            memory_interception=_NO,
            model_context_interception=_NO,
            tool_egress_interception=_NO,
            physical_purge=_NA,
            session_reset="partial: taint recorded from state['session_id']; no reset signal",
            tested_upstream_versions={"langgraph": "not-imported"},
            enforcement_level="ENFORCING",
            conformance_subject="langgraph guard_node",
            notes="Duck-typed: langgraph is never imported and no langgraph release is tested. Only wrapped nodes are covered; tools and unwrapped nodes are not.",
        ),
        Manifest(
            adapter="llamaindex",
            source_ingestion="partial: IngestionCallback registers nodes as chunk derivatives of a supplied parent",
            parent_preservation="supported: chunk (shared or per-node parents)",
            retrieval_interception="supported",
            memory_interception=_NO,
            model_context_interception=_NO,
            tool_egress_interception=_NO,
            physical_purge=_NA,
            session_reset=_TAINT,
            tested_upstream_versions={"llama-index-core": ">=0.11"},
            enforcement_level="ENFORCING",
            conformance_subject="GuardedLlamaRetriever",
            exercised_versions={"llama-index-core": "0.14.25"},
            notes="Retrieval path only; query engines/synthesizers on an unwrapped retriever and direct docstore access are unmediated. Does not own the index store, so purge is the caller's.",
        ),
        Manifest(
            adapter="acs",
            source_ingestion=_NO,
            parent_preservation="supported: memory (parents from active context or session taint)",
            retrieval_interception="supported",
            memory_interception="supported",
            model_context_interception=_NO,
            tool_egress_interception="partial: before_tool_call / before_message_send check session dependence only; no argument or message DLP",
            physical_purge=_NA,
            session_reset="supported: required_action=session_reset",
            tested_upstream_versions={"acs": "draft hook semantics, adapter contract v0"},
            enforcement_level="ENFORCING",
            conformance_subject="AcsContextGuard",
            notes="Targets ACS draft hook semantics; only hooks the host runtime invokes are enforced.",
        ),
        Manifest(
            adapter="model_gateway",
            source_ingestion=_NO,
            parent_preservation="supported: model output (registered as derivative of the authorized context items)",
            retrieval_interception=_NA,
            memory_interception=_NO,
            model_context_interception="supported",
            tool_egress_interception="partial: tool names passed to authorize; tool arguments and results not inspected",
            physical_purge=_NA,
            session_reset="partial: taint recorded via session_id; no reset signal",
            tested_upstream_versions={"openai": "not-imported"},
            enforcement_level="ENFORCING",
            notes=(
                "Provider-neutral; no provider SDK imported. Not in the adapter conformance suite "
                f"(covered by sdk-python/tests/test_gateway.py). {_gateway_constants()}"
            ).strip(),
        ),
    ]


def manifest_json(manifests: list[Manifest] | None = None) -> str:
    return json.dumps([m.to_dict() for m in (manifests or manifest_report())], indent=2, sort_keys=True)
