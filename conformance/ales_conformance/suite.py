"""Wire the in-repo adapters through the contracts."""

from __future__ import annotations

from ales_adapters.live_stores import is_available

from .contract import AdapterConformance, ConformanceReport, IngestionConformance
from .subjects import (
    AcsRetrievalSubject,
    CacheSubject,
    LangGraphSubject,
    LlamaIndexSubject,
    PgVectorNativeSubject,
    QdrantSubject,
    RedisCacheSubject,
    Testbed,
    VectorStoreSubject,
    fs_factory,
)

# (subject class, live store it needs); skipped with no report row when the store is unreachable.
LIVE_SUBJECTS = (
    (QdrantSubject, "qdrant"),
    (PgVectorNativeSubject, "pgvector"),
    (RedisCacheSubject, "redis"),
)


def run_all(include_live: bool = True) -> list[ConformanceReport]:
    reports: list[ConformanceReport] = []
    for cls in (VectorStoreSubject, CacheSubject, LlamaIndexSubject, AcsRetrievalSubject):  # purge-capable: wired to a real outbox + registry
        with Testbed() as tb:
            reports.append(AdapterConformance(cls(tb.client, tb), tb.client).run())
    if include_live:
        for lcls, store in LIVE_SUBJECTS:
            if not is_available(store):
                continue
            with Testbed() as tb:
                subject = lcls(tb.client, tb)
                try:
                    reports.append(AdapterConformance(subject, tb.client).run())
                finally:
                    subject.close()
    with Testbed() as tb:  # purge not applicable: the middleware holds no data of its own
        reports.append(AdapterConformance(LangGraphSubject(tb.client), tb.client).run())
    with Testbed() as tb:
        reports.append(
            IngestionConformance("fs_source (FilesystemSourceConnector)", tb.client, fs_factory).run()
        )
    return reports
