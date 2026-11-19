"""RFC 8785 (JCS) conformance of canonicalisation and signing semantics."""

from __future__ import annotations

import json
import struct
import uuid

import pytest
from ales_core import (
    CanonicalizationError,
    RevocationEvent,
    canonical_bytes,
    canonicalize,
    sign_envelope,
    sign_event,
    sign_model,
    verify_envelope,
    verify_event,
)
from core_fixtures import NOW, make_env
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# RFC 8785 Appendix B: IEEE-754 bit pattern -> expected serialisation.
NUMBER_VECTORS = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


@pytest.mark.parametrize("bits,expected", NUMBER_VECTORS)
def test_rfc8785_appendix_b_numbers(bits, expected):
    value = struct.unpack(">d", bytes.fromhex(bits))[0]
    assert canonicalize(value).decode() == expected


@pytest.mark.parametrize("bits", ["7fffffffffffffff", "7ff0000000000000", "fff0000000000000"])
def test_nan_and_infinity_rejected(bits):
    with pytest.raises(CanonicalizationError):
        canonicalize(struct.unpack(">d", bytes.fromhex(bits))[0])


def test_rfc8785_section_3_2_2_sample():
    raw = (
        '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],'
        '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"/",'
        '"literals":[null,true,false]}'
    )
    expected = (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )
    assert canonicalize(json.loads(raw)).decode("utf-8") == expected


def test_rfc8785_section_3_2_3_key_sorting_is_utf16_code_units():
    raw = (
        '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh",'
        '"1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control",'
        '"\\u00f6":"Latin Small Letter O With Diaeresis"}'
    )
    out = canonicalize(json.loads(raw)).decode("utf-8")
    keys = list(json.loads(out).keys())
    # UTF-16 order puts the emoji (surrogate pair D83D..) BEFORE U+FB33, unlike code-point order.
    assert keys == ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]
    # and the bytes are the compact, unescaped-where-allowed form
    assert out.startswith('{"\\r":"Carriage Return","1":"One","\u0080":"Control"')


def test_key_order_and_whitespace_independent():
    a = canonicalize({"b": [1, {"z": 1, "a": 2}], "a": "x"})
    b = canonicalize(json.loads('{ "a" : "x",\n "b":[1,{"a":2,"z":1}] }'))
    assert a == b == b'{"a":"x","b":[1,{"a":2,"z":1}]}'


def test_string_escaping_minimal():
    assert canonicalize('a\x00\x1f"\\/\x7f ').decode("utf-8") == '"a\\u0000\\u001f\\"\\\\/\x7f "'


def test_integers_beyond_2_53_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize(2**53 + 1)


# ------------------------------------------------------------------ signing semantics
def _event(**kw) -> RevocationEvent:
    base = {
        "event_id": str(uuid.uuid4()),
        "tenant_id": "tenant-a",
        "source_id": str(uuid.uuid4()),
        "reason": "deleted",
        "effective_at": NOW,
    }
    base.update(kw)
    return RevocationEvent(**base)


def test_canonical_bytes_excludes_signature_and_issuer_key_id():
    env = make_env()
    base = canonical_bytes(env)
    assert canonical_bytes(env.model_copy(update={"signature": "AAAA", "issuer_key_id": "k1"})) == base
    assert b"signature" not in base and b"issuer_key_id" not in base
    # dict form of the same object canonicalises identically
    assert canonical_bytes(env.model_dump(mode="json")) == base


def test_sign_verify_roundtrip_ignores_issuer_key_id_but_not_content():
    key = Ed25519PrivateKey.generate()
    env = make_env()
    stamped = sign_model(env, key, "k1")
    assert stamped.issuer_key_id == "k1" and verify_envelope(stamped, key.public_key())
    # swapping the key id label does not invalidate the signature (it is not signed)
    assert verify_envelope(stamped.model_copy(update={"issuer_key_id": "other"}), key.public_key())
    for field, value in (("object_version", "v2"), ("classification", "public"), ("tenant_id", "tenant-b")):
        tampered = stamped.model_copy(update={field: value})
        assert not verify_envelope(tampered, key.public_key()), field


def test_event_scope_and_time_are_signed():
    key = Ed25519PrivateKey.generate()
    ev = _event(affected_scope={"principals": ["bob"]})
    ev = ev.model_copy(update={"signature": sign_event(ev, key)})
    assert verify_event(ev, key.public_key())
    widened = ev.model_copy(update={"affected_scope": None})
    assert not verify_event(widened, key.public_key())
    delayed = ev.model_copy(update={"effective_at": NOW.replace(year=2030)})
    assert not verify_event(delayed, key.public_key())


def test_verify_rejects_garbage_signatures():
    key = Ed25519PrivateKey.generate()
    env = make_env()
    for sig in (None, "", "not base64!!", "AAAA", sign_envelope(env, Ed25519PrivateKey.generate())):
        assert not verify_envelope(env.model_copy(update={"signature": sig}), key.public_key())


def test_signature_stable_across_dict_roundtrip():
    key = Ed25519PrivateKey.generate()
    ev = _event()
    sig = sign_event(ev, key)
    wire = json.loads(ev.model_dump_json())
    wire["signature"] = sig
    assert verify_event(wire, key.public_key())
    assert verify_event(RevocationEvent.model_validate(wire), key.public_key())
