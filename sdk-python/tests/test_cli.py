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
