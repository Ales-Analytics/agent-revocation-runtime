"""Per-adapter coverage declaration (spec: OBSERVE_ONLY adapters are excluded from coverage claims)."""

from __future__ import annotations

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
}
