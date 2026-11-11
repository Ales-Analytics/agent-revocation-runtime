"""Vertical-slice adapters that put ALES INVARIANT enforcement at the edges of common data paths."""

from .coverage import ADAPTER_COVERAGE
from .fs_source import FilesystemSourceConnector
from .langgraph_middleware import guard_node, register_output
from .pgvector_store import GuardedVectorStore, InMemoryVectorBackend, PgVectorBackend, SearchHit
from .redis_cache import DictRedis, GuardedCache

__all__ = [
    "ADAPTER_COVERAGE",
    "DictRedis",
    "FilesystemSourceConnector",
    "GuardedCache",
    "GuardedVectorStore",
    "InMemoryVectorBackend",
    "PgVectorBackend",
    "SearchHit",
    "guard_node",
    "register_output",
]
