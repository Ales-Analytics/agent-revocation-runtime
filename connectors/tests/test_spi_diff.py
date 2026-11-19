"""SPI diff-algorithm tests; semantics mirror adapters/tests/test_fs_source.py."""

import hashlib
from typing import Any

import pytest
from ales_connectors import (
    FileCheckpoint,
    InMemoryCheckpoint,
    PollingConnector,
    RemoteObject,
    SourceConnector,
    acl_narrowed,
)
from ales_connectors.spi import FAIL_CLOSED_ACL, parse_acl_sidecar
from connectors_fixtures import reasons, revocations


class FakeRemote(PollingConnector):
    source_system = "fake"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.store: dict[str, tuple[bytes, dict[str, Any] | None]] = {}
        self.fail = False
        self.digest_calls = 0

    def put(self, oid, content: bytes, acl=None):
        self.store[oid] = (content, acl)

    def list_objects(self):
        if self.fail:
            raise ConnectionError("remote down")
        return [
            RemoteObject(oid, hashlib.md5(c).hexdigest(), None, acl) for oid, (c, acl) in self.store.items()
        ]

    def resolve_digest(self, obj):
        self.digest_calls += 1
        return hashlib.sha256(self.store[obj.id][0]).hexdigest(), "sha256"


def _c(client, **kw):
    return FakeRemote(client, "t1", "fake-1", **kw)


def test_satisfies_spi(client):
    assert isinstance(_c(client), SourceConnector)


def test_scan_registers_and_is_idempotent(client, server):
    c = _c(client)
    c.put("a", b"alpha")
    c.put(
        "b",
        b"beta",
        {"classification": "confidential", "principal_scope": ["alice"], "purpose_scope": ["support"]},
    )
    envs = c.scan()
    by = {e["object_id"]: e for e in envs}
    assert by["a"]["classification"] == "internal" and "principal_scope" not in by["a"]
    assert len(by["a"]["object_version"]) == 12
    assert by["b"]["classification"] == "confidential" and by["b"]["principal_scope"] == ["alice"]
    assert by["a"]["content_digest"] == "sha256:" + hashlib.sha256(b"alpha").hexdigest()
    assert set(server.envelopes) == {e["context_id"] for e in envs}
    assert c.scan() == []
    assert c.watch_once() == []
    assert revocations(server) == []


def test_watch_registers_new_objects(client, server):
    c = _c(client)
    c.put("a", b"alpha")
    c.scan()
    c.put("n", b"new")
    assert c.watch_once() == []
    assert len(server.envelopes) == 2


def test_checkpoint_survives_restart(client, server, tmp_path):
    ck = FileCheckpoint(tmp_path / "ck.json")
    c = _c(client, checkpoint=ck)
    c.put("a", b"alpha")
    c.scan()
    c2 = _c(client, checkpoint=FileCheckpoint(tmp_path / "ck.json"))
    c2.put("a", b"alpha")
    assert "a" in c2.state
    assert c2.watch_once() == [] and revocations(server) == []
    del c2.store["a"]
    assert reasons(c2.watch_once()) == ["deleted"]


def test_delete_emits_deleted_once(client, server):
    c = _c(client)
    c.put("a", b"alpha")
    (env,) = c.scan()
    del c.store["a"]
    evs = c.watch_once()
    assert reasons(evs) == ["deleted"]
    assert evs[0]["source_id"] == env["context_id"] and evs[0]["source_version"] == env["object_version"]
    assert c.watch_once() == []
    assert len(revocations(server)) == 1


def test_content_change_supersedes_and_registers_new_context(client, server):
    c = _c(client)
    c.put("a", b"v1")
    (old,) = c.scan()
    c.put("a", b"v2")
    evs = c.watch_once()
    assert reasons(evs) == ["version_superseded"] and evs[0]["source_id"] == old["context_id"]
    new = [e for e in server.envelopes.values() if e["context_id"] != old["context_id"]]
    assert len(new) == 1 and new[0]["object_version"] != old["object_version"]
    assert c.watch_once() == []


def test_unchanged_hint_does_not_recompute_digest(client):
    c = _c(client)
    c.put("a", b"v1")
    c.scan()
    calls = c.digest_calls
    c.watch_once()
    c.watch_once()
    assert c.digest_calls == calls


def test_hint_change_same_content_is_silent(client, server):
    c = _c(client)
    c.put("a", b"same")
    c.scan()
    c.store["a"] = (b"same", None)
    orig = c.list_objects
    c.list_objects = lambda: [RemoteObject("a", "other-etag", None, None)]  # type: ignore[method-assign]
    assert c.watch_once() == []
    c.list_objects = orig  # type: ignore[method-assign]
    assert revocations(server) == []


@pytest.mark.parametrize(
    "old,new",
    [
        ({"classification": "internal"}, {"classification": "restricted"}),
        ({"principal_scope": ["alice", "bob"]}, {"principal_scope": ["alice"]}),
        ({"purpose_scope": ["a", "b"]}, {"purpose_scope": ["a"]}),
        ({}, {"principal_scope": ["alice"]}),  # unrestricted -> restricted
        ({"principal_scope": ["alice"]}, {"principal_scope": []}),
    ],
)
def test_acl_narrowing_revokes_and_reregisters(client, server, old, new):
    c = _c(client)
    c.put("a", b"x", old)
    (e0,) = c.scan()
    c.put("a", b"x", new)
    evs = c.watch_once()
    assert reasons(evs) == ["acl_changed"] and evs[0]["source_id"] == e0["context_id"]
    assert len(server.envelopes) == 2
    assert c.watch_once() == []


@pytest.mark.parametrize(
    "old,new",
    [
        ({"classification": "confidential"}, {"classification": "internal"}),
        ({"principal_scope": ["alice"]}, {"principal_scope": ["alice", "bob"]}),
        ({"principal_scope": ["alice"]}, {}),  # restricted -> unrestricted
    ],
)
def test_acl_widening_is_silent_reregister(client, server, old, new):
    c = _c(client)
    c.put("a", b"x", old)
    c.scan()
    c.put("a", b"x", new)
    assert c.watch_once() == []
    assert revocations(server) == []
    assert len(server.envelopes) == 2  # re-registered with the wider ACL
    assert c.watch_once() == []


def test_acl_narrowed_unit():
    base = {"classification": "internal", "principal_scope": None, "purpose_scope": None}
    assert not acl_narrowed(base, base)
    assert acl_narrowed(base, {**base, "classification": "confidential"})
    assert not acl_narrowed({**base, "principal_scope": ["a"]}, base)


def test_listing_failure_raises_and_never_emits_deletes(client, server):
    c = _c(client)
    c.put("a", b"alpha")
    c.scan()
    c.fail = True
    with pytest.raises(ConnectionError):
        c.watch_once()
    assert revocations(server) == []
    assert "a" in c.state
    h = c.health()
    assert any("remote down" in e for e in h.errors)


def test_health_reports_polling_sla_honestly(client, clock):
    c = _c(client, poll_interval_seconds=30, clock=clock)
    assert c.health().last_sync is None and c.health().lag_seconds is None
    c.put("a", b"x")
    c.scan()
    clock.t += 45
    h = c.health()
    assert h.mode == "polling" and h.freshness_sla_seconds == 30
    assert h.lag_seconds == pytest.approx(45)
    assert h.coverage == {"deleted": True, "version_superseded": True, "acl_changed": True}
    assert "not real-time" in h.details["note"].lower()


def test_sidecar_parse_fails_closed():
    assert parse_acl_sidecar(None)["classification"] == "internal"
    assert parse_acl_sidecar(b"{not json") == FAIL_CLOSED_ACL
    assert parse_acl_sidecar(b'{"classification": "bogus"}') == FAIL_CLOSED_ACL
    assert parse_acl_sidecar(b'["x"]') == FAIL_CLOSED_ACL
    assert parse_acl_sidecar(b'{"classification": "restricted"}')["classification"] == "restricted"


def test_checkpoint_stores_roundtrip(tmp_path):
    for s in (InMemoryCheckpoint(), FileCheckpoint(tmp_path / "x" / "c.json")):
        assert s.get("k") is None and s.get("k", 5) == 5
        s.put("k", {"a": [1, 2]})
        s.put("j", 1)
        assert s.get("k") == {"a": [1, 2]} and s.get("j") == 1
