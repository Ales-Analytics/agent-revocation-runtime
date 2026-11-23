# Coverage matrix

Run date (UTC): 2026-11-23

| adapter | store | checks passed | purges | level |
|---|---|---|---|---|
| GuardedVectorStore (InMemory backend) | in-memory | 6/6 | pass | ENFORCING |
| GuardedCache (DictRedis) | in-memory | 6/6 | pass | ENFORCING |
| GuardedLlamaRetriever (fake retriever) | in-memory | 6/6 | pass | ENFORCING |
| AcsContextGuard (after_knowledge_retrieval) | in-memory | 6/6 | pass | ENFORCING |
| GuardedVectorStore (Qdrant, live) | live store | 6/6 | pass | ENFORCING |
| GuardedVectorStore (pgvector native, live) | live store | 6/6 | pass | ENFORCING |
| GuardedCache (Redis, live) | live store | 6/6 | pass | ENFORCING |
| langgraph guard_node (fake node) | in-memory | 5/5 | n/a | ENFORCING |
| fs_source (FilesystemSourceConnector) | filesystem | 6/6 | n/a | INGESTION_ONLY |

Each row covers reads through the named adapter. A live-store purge pass means the contract
also checked the raw store after dispatch. The LangGraph and LlamaIndex contract rows use
stand-ins for the node and retriever. S3, Azure Blob and webhook ingestion have no conformance
run in this suite. See the [individual checks and manifests](../conformance/report.md).
