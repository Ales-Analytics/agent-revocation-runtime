import pytest
from ales_conformance.contract import AdapterConformance, ObjectRef, ReadOutcome
from ales_conformance.report import render_markdown, write_report
from ales_conformance.subjects import CacheSubject, LangGraphSubject, Testbed, VectorStoreSubject
from ales_conformance.suite import run_all


@pytest.mark.parametrize("cls", [VectorStoreSubject, CacheSubject, LangGraphSubject])
def test_enforcing_adapters_pass_contract(cls):
    with Testbed() as tb:
        rep = AdapterConformance(cls(tb.client), tb.client).run()
    failed = [(c.id, c.detail) for c in rep.checks if not c.passed]
    assert rep.passed and rep.enforcement_level == "ENFORCING", failed
    assert [c.id for c in rep.checks] == ["a", "b", "c", "d", "e"]


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
    assert "| adapter | checks passed | level |" in text
    assert text.count("ENFORCING") >= 3 and "INGESTION_ONLY" in text
    out = write_report(reports, tmp_path / "report.md")
    assert out.read_text(encoding="utf-8") == text
