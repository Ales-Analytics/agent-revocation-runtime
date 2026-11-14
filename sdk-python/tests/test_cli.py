import io

from ales_sdk import InvariantClient, cli


def test_demo_happy_path_flips_allow_to_deny(make_client, server):
    c = make_client()
    out = io.StringIO()
    assert cli.run_revoke_rag_source(c, out) is True
    text = out.getvalue()
    assert "OVERALL: PASS" in text and "FAIL" not in text
    paths = [p for _, p, _ in server.requests]
    assert paths.index("/v1/revocations") > paths.index("/v1/authorize")
    assert paths.count("/v1/authorize") == 2
    assert paths.count("/v1/derivations") == 3


def test_demo_reports_fail_when_server_ignores_revocation(make_client, server):
    server.ignore_revocations = True
    out = io.StringIO()
    assert cli.run_revoke_rag_source(make_client(), out) is False
    assert "OVERALL: FAIL" in out.getvalue()


def test_demo_stub_without_server(monkeypatch, capsys):
    monkeypatch.delenv("ALES_BASE_URL", raising=False)
    assert cli.main(["demo", "--scenario", "revoke-rag-source"]) == 0
    assert "examples/" in capsys.readouterr().out


def test_demo_unreachable_exits_zero(monkeypatch, capsys):
    monkeypatch.setenv("ALES_BASE_URL", "http://127.0.0.1:1")
    assert cli.main(["demo"]) == 0
    assert "unreachable" in capsys.readouterr().out


def test_init_writes_toml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["init", "--local"]) == 0
    assert "http://localhost:8787" in (tmp_path / "ales.toml").read_text()


def test_status_and_verify_via_mock(monkeypatch, server, capsys):
    monkeypatch.setattr(
        cli, "_make_client", lambda **kw: InvariantClient("http://ales.test", "t1", auth_token="tok", transport=server.transport())
    )
    assert cli.main(["status"]) == 0
    assert cli.main(["verify", "--adapter", "x", "--mode", "strict"]) == 0
    assert '"passed": true' in capsys.readouterr().out


# ---------------------------------------------------------------------------- diagnostics
import json

import httpx
import pytest

_MANIFESTS = [
    {
        "adapter": "llamaindex", "enforcement_level": "ENFORCING", "source_ingestion": "partial: x",
        "parent_preservation": "supported: chunk", "retrieval_interception": "supported",
        "memory_interception": "unsupported", "model_context_interception": "unsupported",
        "tool_egress_interception": "unsupported", "physical_purge": "n/a", "session_reset": "partial: t",
        "tested_upstream_versions": {"llama-index-core": ">=0.11", "langgraph": "not-imported"}, "notes": "n",
    },
    {
        "adapter": "qdrant", "enforcement_level": "ENFORCING", "source_ingestion": "unsupported",
        "parent_preservation": "supported: chunk", "retrieval_interception": "supported",
        "memory_interception": "unsupported", "model_context_interception": "unsupported",
        "tool_egress_interception": "unsupported", "physical_purge": "supported", "session_reset": "partial: t",
        "tested_upstream_versions": {}, "notes": "",
    },
]


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for k in ("ALES_BASE_URL", "ALES_AUTH_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(cli, "_load_manifests", lambda: _MANIFESTS)
    monkeypatch.setattr(cli, "_REPO_ROOT", tmp_path)
    return tmp_path


def _transport(ready=True, ephemeral=False):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/healthz":
            return httpx.Response(200, json={"status": "ok"})
        if req.url.path == "/v1/readyz":
            return httpx.Response(200 if ready else 503, json={"status": "ok" if ready else "not ready"})
        if req.url.path == "/v1/snapshot/public_key":
            return httpx.Response(200, json={"key_id": "k1", "public_key_b64": "x", "ephemeral": ephemeral})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _patch_client(monkeypatch, **kw):
    monkeypatch.setattr(
        cli, "_make_client",
        lambda **_: InvariantClient("http://ales.test", "t1", auth_token="tok", transport=_transport(**kw), max_retries=0),
    )


def test_doctor_no_server_warns_but_passes(isolated, capsys):
    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "PASS  ales_sdk" in out and "WARN  config" in out and "WARN  server" in out
    assert "ales_server.preflight" in out


def test_doctor_server_ok(isolated, monkeypatch, capsys):
    _patch_client(monkeypatch)
    monkeypatch.setenv("ALES_AUTH_TOKEN", "tok")
    assert cli.main(["doctor", "--server", "http://ales.test"]) == 0
    out = capsys.readouterr().out
    assert "PASS  healthz" in out and "PASS  readyz" in out and "PASS  snapshot key" in out


def test_doctor_not_ready_fails(isolated, monkeypatch, capsys):
    _patch_client(monkeypatch, ready=False)
    assert cli.main(["doctor", "--server", "http://ales.test"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  readyz" in out and "WARN  snapshot key" in out


def test_doctor_ephemeral_key_warns_and_bad_config_fails(isolated, monkeypatch, capsys):
    _patch_client(monkeypatch, ephemeral=True)
    monkeypatch.setenv("ALES_AUTH_TOKEN", "tok")
    assert cli.main(["doctor", "--server", "http://ales.test"]) == 0
    assert "EPHEMERAL" in capsys.readouterr().out
    (isolated / "ales.toml").write_text("base_url = [", encoding="utf-8")
    assert cli.main(["doctor"]) == 1
    assert "FAIL  config" in capsys.readouterr().out


def test_doctor_unreachable_server_fails(isolated, monkeypatch, capsys):
    def boom(req):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(
        cli, "_make_client",
        lambda **_: InvariantClient("http://ales.test", "t1", allow_anonymous=True, transport=httpx.MockTransport(boom), max_retries=0),
    )
    assert cli.main(["doctor", "--server", "http://ales.test"]) == 1
    assert "FAIL  healthz" in capsys.readouterr().out


def test_doctor_without_adapters_installed(isolated, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_load_manifests", lambda: None)
    assert cli.main(["doctor"]) == 0
    assert "WARN  ales_adapters" in capsys.readouterr().out


def test_integrations_inspect(isolated, capsys):
    assert cli.main(["integrations", "inspect"]) == 0
    out = capsys.readouterr().out
    assert "llamaindex  [ENFORCING]" in out and "retrieval_interception" in out and "llama-index-core" in out


def test_integrations_inspect_not_installed(isolated, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_load_manifests", lambda: None)
    assert cli.main(["integrations", "inspect"]) == 1
    assert "not installed" in capsys.readouterr().out


_REPORT = """# Adapter conformance

## Capability manifests

| adapter | enforcement | retrieval | conformance |
|---|---|---|---|
| llamaindex | ENFORCING | supported | VERIFIED |
| qdrant | ENFORCING | supported | UNVERIFIED |

## Checks
"""


def test_coverage_report_merges_conformance_states(isolated, capsys):
    (isolated / "conformance").mkdir()
    (isolated / "conformance" / "report.md").write_text(_REPORT, encoding="utf-8")
    assert cli.main(["coverage", "report", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {a["adapter"]: a["conformance"] for a in data["adapters"]} == {"llamaindex": "VERIFIED", "qdrant": "UNVERIFIED"}
    assert cli.main(["coverage", "report"]) == 0
    assert "UNVERIFIED retrieval claims: qdrant" in capsys.readouterr().out


def test_coverage_report_without_report_file(isolated, capsys):
    assert cli.main(["coverage", "report", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["conformance_report"] is None and all(a["conformance"] == "UNKNOWN" for a in data["adapters"])
