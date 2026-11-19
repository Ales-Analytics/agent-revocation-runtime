import json

import pytest
from ales_connectors import (
    SourceConnector,
    WebhookAuthError,
    WebhookConnector,
    WebhookPayloadError,
    WebhookReplayError,
    sign_body,
)
from connectors_fixtures import reasons, revocations

SECRET = "whsec_test"


@pytest.fixture
def wh(client, clock):
    return WebhookConnector(client, "t1", shared_secret=SECRET, clock=clock, max_skew_seconds=300)


def _send(wh, clock, payload, *, secret=SECRET, ts=None, raw=True):
    body = {**payload, "timestamp": clock.t if ts is None else ts}
    rb = json.dumps(body).encode()
    return wh.handle(body, signature_header=sign_body(rb, secret), raw_body=rb if raw else None)


def test_satisfies_spi(wh):
    assert isinstance(wh, SourceConnector)
    assert wh.scan() == []


def test_valid_update_registers_then_supersedes(wh, clock, server):
    r = _send(
        wh,
        clock,
        {
            "action": "updated",
            "object_id": "doc1",
            "version": "v1",
            "acl": {"classification": "confidential", "principal_scope": ["alice"]},
        },
    )
    assert r.envelope and r.envelope["classification"] == "confidential" and r.events == []
    assert r.envelope["object_version"] and len(r.envelope["object_version"]) == 12
    clock.t += 1
    r2 = _send(wh, clock, {"action": "updated", "object_id": "doc1", "version": "v2"})
    assert reasons(r2.events) == ["version_superseded"]
    assert r2.events[0]["source_id"] == r.envelope["context_id"]
    assert r2.envelope["classification"] == "confidential"  # ACL carried over when omitted
    assert reasons(wh.watch_once()) == ["version_superseded"]
    assert wh.watch_once() == []  # drained


def test_explicit_digest_used(wh, clock):
    d = "ab" * 32
    r = _send(wh, clock, {"action": "updated", "object_id": "d", "version": "1", "digest": d})
    assert r.envelope["content_digest"] == "sha256:" + d
    assert r.envelope["object_version"] == d[:12]


def test_acl_changed_narrow_and_widen(wh, clock, server):
    _send(
        wh,
        clock,
        {"action": "updated", "object_id": "d", "version": "1", "acl": {"principal_scope": ["a", "b"]}},
    )
    clock.t += 1
    r = _send(
        wh,
        clock,
        {"action": "acl_changed", "object_id": "d", "version": "1", "acl": {"principal_scope": ["a"]}},
    )
    assert reasons(r.events) == ["acl_changed"]
    clock.t += 1
    r = _send(
        wh,
        clock,
        {"action": "acl_changed", "object_id": "d", "version": "1", "acl": {"principal_scope": ["a", "c"]}},
    )
    assert r.events == [] and r.envelope is not None
    assert len(revocations(server)) == 1


def test_deleted_and_unknown_delete(wh, clock, server):
    _send(wh, clock, {"action": "updated", "object_id": "d", "version": "1"})
    clock.t += 1
    assert reasons(_send(wh, clock, {"action": "deleted", "object_id": "d"}).events) == ["deleted"]
    clock.t += 1
    assert _send(wh, clock, {"action": "deleted", "object_id": "d"}).events == []
    assert len(revocations(server)) == 1


def test_missing_and_invalid_signature(wh, clock, server):
    body = {"action": "deleted", "object_id": "d", "timestamp": clock.t}
    with pytest.raises(WebhookAuthError):
        wh.handle(body, signature_header=None)
    with pytest.raises(WebhookAuthError):
        wh.handle(body, signature_header="")
    with pytest.raises(WebhookAuthError):
        wh.handle(body, signature_header="sha256=" + "0" * 64)
    with pytest.raises(WebhookAuthError):
        _send(wh, clock, {"action": "deleted", "object_id": "d"}, secret="wrong")
    assert wh.rejected == 4 and revocations(server) == []


def test_tampered_body_rejected(wh, clock):
    body = {"action": "updated", "object_id": "d", "version": "1", "timestamp": clock.t}
    rb = json.dumps(body).encode()
    sig = sign_body(rb, SECRET)
    evil = {**body, "object_id": "other"}
    with pytest.raises(WebhookAuthError):
        wh.handle(evil, signature_header=sig, raw_body=json.dumps(evil).encode())


def test_bare_hex_signature_and_canonical_signing_when_no_raw_body(wh, clock):
    from ales_connectors.webhook_source import canonical_body

    body = {"action": "updated", "object_id": "d", "version": "1", "timestamp": clock.t}
    sig = sign_body(canonical_body(body), SECRET).removeprefix("sha256=")
    assert wh.handle(body, signature_header=sig).envelope is not None


def test_per_call_secret_override_and_no_secret(client, clock):
    w = WebhookConnector(client, "t1", clock=clock)
    body = {"action": "deleted", "object_id": "d", "timestamp": clock.t}
    rb = json.dumps(body).encode()
    with pytest.raises(WebhookAuthError):
        w.handle(body, signature_header=sign_body(rb, "s"), raw_body=rb)  # no secret anywhere: fail closed
    assert w.handle(body, signature_header=sign_body(rb, "s"), shared_secret="s", raw_body=rb).events == []


def test_replay_window(wh, clock):
    with pytest.raises(WebhookReplayError):
        _send(wh, clock, {"action": "deleted", "object_id": "d"}, ts=clock.t - 301)
    with pytest.raises(WebhookReplayError):
        _send(wh, clock, {"action": "deleted", "object_id": "d"}, ts=clock.t + 301)
    _send(wh, clock, {"action": "deleted", "object_id": "d"}, ts=clock.t - 299)  # inside window
    # exact replay of an accepted delivery
    body = {"action": "updated", "object_id": "d", "version": "1", "timestamp": clock.t}
    rb = json.dumps(body).encode()
    sig = sign_body(rb, SECRET)
    wh.handle(body, signature_header=sig, raw_body=rb)
    with pytest.raises(WebhookReplayError):
        wh.handle(body, signature_header=sig, raw_body=rb)
    # after the window the same body is stale by timestamp
    clock.t += 301
    with pytest.raises(WebhookReplayError):
        wh.handle(body, signature_header=sig, raw_body=rb)


def test_timestamp_required_and_iso_accepted(wh, clock):
    body = {"action": "deleted", "object_id": "d"}
    rb = json.dumps(body).encode()
    with pytest.raises(WebhookReplayError):
        wh.handle(body, signature_header=sign_body(rb, SECRET), raw_body=rb)
    bad = {**body, "timestamp": "not-a-time"}
    rb = json.dumps(bad).encode()
    with pytest.raises(WebhookPayloadError):
        wh.handle(bad, signature_header=sign_body(rb, SECRET), raw_body=rb)
    clock.t = 1_700_000_000.0
    iso = {**body, "timestamp": "2023-11-14T22:13:20Z"}
    rb = json.dumps(iso).encode()
    assert wh.handle(iso, signature_header=sign_body(rb, SECRET), raw_body=rb).events == []


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "explode", "object_id": "d"},
        {"action": "updated", "object_id": ""},
        {"action": "updated", "object_id": "d"},  # no version
        {"action": "updated", "object_id": "d", "version": "1", "digest": "xyz"},
        {"action": "updated", "object_id": "d", "version": "1", "acl": {"classification": "bogus"}},
        {"action": "acl_changed", "object_id": "d", "version": "1"},  # no acl
        {"action": "acl_changed", "object_id": "unknown", "version": "1", "acl": {}},
    ],
)
def test_payload_validation(wh, clock, payload):
    with pytest.raises(WebhookPayloadError):
        _send(wh, clock, payload)


def test_health_is_events_mode(wh, clock):
    h = wh.health()
    assert h.mode == "events" and h.last_sync is None
    _send(wh, clock, {"action": "updated", "object_id": "d", "version": "1"})
    assert wh.health().last_sync == clock.t
    assert "reconcile" in wh.health().details["note"]
