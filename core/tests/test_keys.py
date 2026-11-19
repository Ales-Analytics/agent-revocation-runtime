from __future__ import annotations

import uuid

import pytest
from ales_core import (
    KeyRegistry,
    KeyRegistryError,
    RevocationEvent,
    sign_model,
    verify_with_registry,
)
from core_fixtures import NOW, TENANT, make_env
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture
def reg(session):
    return KeyRegistry(session)


def _event(tenant=TENANT):
    return RevocationEvent(
        event_id=str(uuid.uuid4()),
        tenant_id=tenant,
        source_id=str(uuid.uuid4()),
        reason="deleted",
        effective_at=NOW,
    )


def test_ok_for_envelope_and_event(session, reg):
    k = Ed25519PrivateKey.generate()
    reg.register_key(TENANT, "k1", k.public_key())
    assert verify_with_registry(session, sign_model(make_env(), k, "k1")).reason == "ok"
    r = verify_with_registry(session, sign_model(_event(), k, "k1"))
    assert r.ok and r.reason == "ok" and r.key_id == "k1"


def test_missing_signature(session, reg):
    k = Ed25519PrivateKey.generate()
    reg.register_key(TENANT, "k1", k.public_key())
    r = verify_with_registry(session, make_env().model_copy(update={"issuer_key_id": "k1"}))
    assert not r.ok and r.reason == "missing_signature" and not bool(r)


def test_unknown_key_and_missing_key_id(session, reg):
    k = Ed25519PrivateKey.generate()
    signed = sign_model(make_env(), k, "ghost")
    assert verify_with_registry(session, signed).reason == "unknown_key"
    no_id = signed.model_copy(update={"issuer_key_id": None})
    assert verify_with_registry(session, no_id).reason == "unknown_key"


def test_bad_signature(session, reg):
    k = Ed25519PrivateKey.generate()
    reg.register_key(TENANT, "k1", k.public_key())
    signed = sign_model(make_env(), k, "k1")
    assert (
        verify_with_registry(session, signed.model_copy(update={"object_version": "v9"})).reason
        == "bad_signature"
    )
    other = sign_model(make_env(), Ed25519PrivateKey.generate(), "k1")
    assert verify_with_registry(session, other).reason == "bad_signature"
    assert (
        verify_with_registry(session, signed.model_copy(update={"signature": "!!!"})).reason
        == "bad_signature"
    )


def test_cross_tenant_key(session, reg):
    k = Ed25519PrivateKey.generate()
    reg.register_key("tenant-b", "kb", k.public_key())
    signed = sign_model(make_env(tenant=TENANT), k, "kb")
    assert verify_with_registry(session, signed).reason == "cross_tenant_key"
    # even when that key is revoked, the answer does not leak the other tenant's key state
    reg.set_status("tenant-b", "kb", "revoked")
    assert verify_with_registry(session, signed).reason == "cross_tenant_key"


@pytest.mark.parametrize("status", ["retired", "revoked"])
def test_key_not_active(session, reg, status):
    k = Ed25519PrivateKey.generate()
    reg.register_key(TENANT, "k1", k.public_key())
    signed = sign_model(make_env(), k, "k1")
    assert verify_with_registry(session, signed).ok
    reg.set_status(TENANT, "k1", status)
    assert verify_with_registry(session, signed).reason == "key_not_active"
    assert reg.get_active(TENANT, "k1") is None


def test_rotation_new_key_valid_old_rejected(session, reg):
    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    reg.register_key(TENANT, "old", old.public_key())
    reg.register_key(TENANT, "new", new.public_key())
    reg.set_status(TENANT, "old", "retired")
    assert verify_with_registry(session, sign_model(make_env(), new, "new")).ok
    assert verify_with_registry(session, sign_model(make_env(), old, "old")).reason == "key_not_active"


def test_registry_rules(session, reg):
    k = Ed25519PrivateKey.generate()
    reg.register_key(TENANT, "k1", k.public_key())
    with pytest.raises(KeyRegistryError):  # key ids are global and never re-bound
        reg.register_key("tenant-b", "k1", k.public_key())
    with pytest.raises(KeyRegistryError):
        reg.register_key(TENANT, "k1", k.public_key())
    with pytest.raises(KeyRegistryError):
        reg.register_key(TENANT, "short", b"\x00" * 31)
    with pytest.raises(KeyRegistryError):
        reg.register_key(TENANT, "bad", "%%%")
    with pytest.raises(KeyRegistryError):
        reg.register_key(TENANT, "badstatus", k.public_key(), status="nope")
    with pytest.raises(KeyRegistryError):  # another tenant cannot touch it
        reg.set_status("tenant-b", "k1", "revoked")
    reg.set_status(TENANT, "k1", "revoked")
    with pytest.raises(KeyRegistryError):  # revoked is terminal
        reg.set_status(TENANT, "k1", "active")
    reg.set_status(TENANT, "k1", "revoked")  # idempotent
    assert reg.get_active("tenant-b", "k1") is None


def test_register_accepts_b64_and_raw(session, reg):
    import base64

    from cryptography.hazmat.primitives import serialization

    k = Ed25519PrivateKey.generate()
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    reg.register_key(TENANT, "kb64", base64.b64encode(raw).decode())
    reg.register_key(TENANT, "kraw", raw)
    for kid in ("kb64", "kraw"):
        assert verify_with_registry(session, sign_model(make_env(), k, kid)).ok


def test_dict_payload_supported(session, reg):
    k = Ed25519PrivateKey.generate()
    reg.register_key(TENANT, "k1", k.public_key())
    wire = sign_model(make_env(), k, "k1").model_dump(mode="json")
    assert verify_with_registry(session, wire).ok
    wire["content_digest"] = "sha256:" + "0" * 64
    assert verify_with_registry(session, wire).reason == "bad_signature"
