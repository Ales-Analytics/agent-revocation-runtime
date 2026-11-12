"""Vertical-slice adapters that put ALES INVARIANT enforcement at the edges of common data paths."""

from .acs_adapter import AcsContextGuard, HookDecision
from .coverage import ADAPTER_COVERAGE
from .fs_source import FilesystemSourceConnector
from .langgraph_middleware import guard_node, register_output
from .llamaindex_adapter import GuardedLlamaRetriever, IngestionCallback
from .pgvector_store import (
    GuardedVectorStore,
    InMemoryVectorBackend,
    PgVectorBackend,
    PgVectorNativeBackend,
    SearchHit,
)
from .purge import CachePurgeTarget, PurgeError, PurgeRegistry, PurgeTarget, VectorPurgeTarget
from .qdrant_store import QdrantBackend
from .redis_cache import DictRedis, GuardedCache

__all__ = [
    "ADAPTER_COVERAGE",
    "AcsContextGuard",
    "CachePurgeTarget",
    "DictRedis",
    "FilesystemSourceConnector",
    "GuardedCache",
    "GuardedLlamaRetriever",
    "GuardedVectorStore",
    "HookDecision",
    "InMemoryVectorBackend",
    "IngestionCallback",
    "PgVectorBackend",
    "PgVectorNativeBackend",
    "PurgeError",
    "PurgeRegistry",
    "PurgeTarget",
    "QdrantBackend",
    "SearchHit",
    "VectorPurgeTarget",
    "guard_node",
    "register_output",
]
