import pytest
from ales_adapters.live_stores import is_available, unavailable_reason
from ales_conformance.contract import AdapterConformance, ObjectRef, ReadOutcome
from ales_conformance.report import render_markdown, write_report
from ales_conformance.subjects import (
    AcsRetrievalSubject,
    CacheSubject,
    LangGraphSubject,
    LlamaIndexSubject,
    PgVectorNativeSubject,
    QdrantSubject,
    RedisCacheSubject,
    Testbed,
    VectorStoreSubject,
)
from ales_conformance.suite import run_all


@pytest.mark.parametrize("cls", [VectorStoreSubject, CacheSubject, LangGraphSubject, LlamaIndexSubject, AcsRetrievalSubject])
def test_enforcing_adapters_pass_contract(cls):
    with Testbed() as tb:
        rep = AdapterConformance(cls(tb.client), tb.client).run()
    failed = [(c.id, c.detail) for c in rep.checks if not c.passed]
    assert rep.passed and rep.enforcement_level == "ENFORCING", failed
    assert [c.id for c in rep.checks] == ["a", "b", "c", "d", "e"]
    assert rep.purges == "n/a"  # no dispatcher wired -> physical purge not exercised


@pytest.mark.parametrize("cls", [VectorStoreSubject, CacheSubject, LlamaIndexSubject, AcsRetrievalSubject])
def test_purge_capable_adapters_pass_physical_purge_check(cls):
    with Testbed() as tb:
        rep = AdapterConformance(cls(tb.client, tb), tb.client).run()
    failed = [(c.id, c.detail) for c in rep.checks if not c.passed]
    assert rep.passed and rep.purges == "pass", failed
    assert [c.id for c in rep.checks] == ["a", "b", "c", "d", "e", "f"]


@pytest.mark.parametrize(
    "cls,store",
    [(QdrantSubject, "qdrant"), (PgVectorNativeSubject, "pgvector"), (RedisCacheSubject, "redis")],
)
def test_live_store_subjects_pass_full_contract(cls, store):
    if not is_available(store):
        pytest.skip(unavailable_reason(store))
    with Testbed() as tb:
        subject = cls(tb.client, tb)
        try:
            rep = AdapterConformance(subject, tb.client).run()
        finally:
            subject.close()
    failed = [(c.id, c.detail) for c in rep.checks if not c.passed]
    assert rep.passed and rep.enforcement_level == "ENFORCING" and rep.purges == "pass", failed
    assert [c.id for c in rep.checks] == ["a", "b", "c", "d", "e", "f"]
    assert rep.store == "live store"


def test_live_rows_appear_in_suite_and_report_only_when_store_is_up(tmp_path):
    reports = run_all()
    live = {r.adapter for r in reports if r.store == "live store"}
    expected = {
        n
        for n, st in (
            (QdrantSubject.name, "qdrant"),
            (PgVectorNativeSubject.name, "pgvector"),
            (RedisCacheSubject.name, "redis"),
        )
        if is_available(st)
    }
    assert live == expected
    text = render_markdown(reports)
    assert text.count("| live store |") == len(expected)
    assert "| in-memory |" in text
    assert run_all(include_live=False) and all(r.store != "live store" for r in run_all(include_live=False))


def test_purge_check_detects_a_store_that_keeps_the_bytes():
    with Testbed() as tb:
        subj = VectorStoreSubject(tb.client, tb)
        subj.purge = lambda: None  # type: ignore[method-assign]  # a "purger" that never deletes
        rep = AdapterConformance(subj, tb.client).run()
    f = next(c for c in rep.checks if c.id == "f")
    assert not f.passed and rep.purges == "FAIL" and not rep.passed
    assert next(c for c in rep.checks if c.id == "b").passed  # enforcement itself still holds


def test_fs_source_event_contract_is_ingestion_only():
    rep = next(r for r in run_all() if r.adapter.startswith("fs_source"))
    failed = [(c.id, c.detail) for c in rep.checks if not c.passed]
    assert rep.passed and rep.enforcement_level == "INGESTION_ONLY", failed


class _LeakySubject:
    """Reads straight from its backing store: never blocks. The suite must catch it."""

    name = "leaky"

    def __init__(self, client):
        self.client, self.data = client, {}

    def ingest(self, parents):
        from ales_sdk import new_derivative

        env = new_derivative("cache", parents, self.client.tenant_id, "leak", "x")
        self.client.register_derivation(env)
        self.data[env["context_id"]] = "secret"
        return ObjectRef(env["context_id"])

    def read(self, ref, principal):
        return ReadOutcome(self.data[ref.context_id])


class _OverBlockingSubject(_LeakySubject):
    name = "overblocker"

    def read(self, ref, principal):
        return ReadOutcome(None, True, ["ANCESTOR_ACL_REVOKED"])


def test_contract_detects_non_enforcing_adapter():
    with Testbed() as tb:
        rep = AdapterConformance(_LeakySubject(tb.client), tb.client).run()
    assert not rep.passed and rep.enforcement_level == "NON_ENFORCING"
    assert not next(c for c in rep.checks if c.id == "b").passed


def test_contract_detects_over_blocking():
    with Testbed() as tb:
        rep = AdapterConformance(_OverBlockingSubject(tb.client), tb.client).run()
    assert not rep.passed
    assert not next(c for c in rep.checks if c.id == "a").passed
    assert not next(c for c in rep.checks if c.id == "e").passed


def test_report_markdown(tmp_path):
    reports = run_all()
    text = render_markdown(reports)
    assert "| adapter | store | checks passed | purges | level |" in text
    assert text.count("| pass |") >= 2 and "| n/a |" in text
    assert text.count("ENFORCING") >= 3 and "INGESTION_ONLY" in text
    out = write_report(reports, tmp_path / "report.md")
    assert out.read_text(encoding="utf-8") == text
