"""Wire the in-repo adapters through the contracts."""

from __future__ import annotations

from .contract import AdapterConformance, ConformanceReport, IngestionConformance
from .subjects import CacheSubject, LangGraphSubject, Testbed, VectorStoreSubject, fs_factory


def run_all() -> list[ConformanceReport]:
    reports: list[ConformanceReport] = []
    for cls in (VectorStoreSubject, CacheSubject, LangGraphSubject):
        with Testbed() as tb:
            reports.append(AdapterConformance(cls(tb.client), tb.client).run())
    with Testbed() as tb:
        reports.append(
            IngestionConformance("fs_source (FilesystemSourceConnector)", tb.client, fs_factory).run()
        )
    return reports
