import json

from ales_adapters.fs_source import FilesystemSourceConnector


def _conn(client, tmp_path):
    return FilesystemSourceConnector(client, tmp_path / "root", "t1", checkpoint_path=tmp_path / "ck.json")


def _revocations(server):
    return [b for m, p, b in server.requests if p == "/v1/revocations"]


def test_scan_registers_files_with_acl_sidecar(client, server, tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("alpha")
    (root / "sub" / "b.txt").write_text("beta")
    (root / "sub" / "b.txt.acl.json").write_text(
        json.dumps(
            {"classification": "confidential", "principal_scope": ["alice"], "purpose_scope": ["support"]}
        )
    )
    envs = _conn(client, tmp_path).scan()
    assert {e["object_id"] for e in envs} == {"a.txt", "sub/b.txt"}
    by_id = {e["object_id"]: e for e in envs}
    assert by_id["a.txt"]["classification"] == "internal"
    assert "principal_scope" not in by_id["a.txt"]
    assert len(by_id["a.txt"]["object_version"]) == 12
    assert by_id["sub/b.txt"]["classification"] == "confidential"
    assert by_id["sub/b.txt"]["principal_scope"] == ["alice"]
    assert set(server.envelopes) == {e["context_id"] for e in envs}


def test_scan_is_idempotent_and_checkpoint_persists(client, server, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("alpha")
    c = _conn(client, tmp_path)
    assert len(c.scan()) == 1
    assert c.scan() == []
    c2 = _conn(client, tmp_path)  # restart
    assert "a.txt" in c2.state
    assert c2.watch_once() == []
    assert _revocations(server) == []


def test_delete_emits_deleted(client, server, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("alpha")
    c = _conn(client, tmp_path)
    (env,) = c.scan()
    (root / "a.txt").unlink()
    (ev,) = c.watch_once()
    assert ev["reason"] == "deleted" and ev["source_id"] == env["context_id"]
    assert env["context_id"] in server.revoked
    assert "a.txt" not in c.state


def test_content_change_supersedes_and_registers_new_version(client, server, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("alpha")
    c = _conn(client, tmp_path)
    (old,) = c.scan()
    (root / "a.txt").write_text("alpha v2")
    (ev,) = c.watch_once()
    assert ev["reason"] == "version_superseded"
    assert ev["source_version"] == old["object_version"]
    new_ctx = c.state["a.txt"]["context_id"]
    assert new_ctx != old["context_id"] and new_ctx in server.envelopes
    assert server.envelopes[new_ctx]["object_version"] != old["object_version"]
    assert new_ctx not in server.revoked


def test_acl_narrowing_emits_acl_changed_but_widening_does_not(client, server, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("alpha")
    sidecar = root / "a.txt.acl.json"
    sidecar.write_text(json.dumps({"principal_scope": ["alice", "bob"]}))
    c = _conn(client, tmp_path)
    (old,) = c.scan()
    sidecar.write_text(json.dumps({"principal_scope": ["alice"]}))
    (ev,) = c.watch_once()
    assert ev["reason"] == "acl_changed" and ev["source_id"] == old["context_id"]
    assert server.envelopes[c.state["a.txt"]["context_id"]]["principal_scope"] == ["alice"]
    # widening: re-registered, no event
    sidecar.write_text(json.dumps({"principal_scope": ["alice", "carol"]}))
    assert c.watch_once() == []
    assert len(_revocations(server)) == 1
    # classification raised -> narrowing
    sidecar.write_text(json.dumps({"classification": "restricted", "principal_scope": ["alice", "carol"]}))
    (ev2,) = c.watch_once()
    assert ev2["reason"] == "acl_changed"
