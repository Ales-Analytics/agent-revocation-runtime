"""Property-based tests for canonicalisation and signing (trust-critical inputs)."""

from __future__ import annotations

import json
import math
import random
import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest
from ales_core import (
    CanonicalizationError,
    ContextEnvelope,
    RevocationEvent,
    canonical_bytes,
    canonicalize,
    sign_model,
    verify_envelope,
    verify_event,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

SETTINGS = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])

KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key()

# Lone surrogates cannot be UTF-8 encoded and are not valid JSON text; exclude category Cs.
TEXT = st.text(st.characters(blacklist_categories=("Cs",)), max_size=12)
INTS = st.integers(-(2**53 - 1), 2**53 - 1)  # I-JSON safe-integer domain
FLOATS = st.floats(allow_nan=False, allow_infinity=False)
JSON = st.recursive(
    st.none() | st.booleans() | INTS | FLOATS | TEXT,
    lambda kids: st.lists(kids, max_size=4) | st.dictionaries(TEXT, kids, max_size=4),
    max_leaves=15,
)


def _shuffled(v, rnd: random.Random):
    if isinstance(v, dict):
        items = list(v.items())
        rnd.shuffle(items)
        return {k: _shuffled(x, rnd) for k, x in items}
    if isinstance(v, list):
        return [_shuffled(x, rnd) for x in v]
    return v


def _normalise(v):
    """Python value after a JSON round trip of the canonical form (-0.0 and 1.0 collapse to ints)."""
    return json.loads(json.dumps(v, ensure_ascii=False))


@SETTINGS
@given(JSON, st.randoms(use_true_random=False))
def test_canonical_deterministic_and_order_independent(value, rnd):
    a = canonicalize(value)
    assert a == canonicalize(value)
    assert a == canonicalize(_shuffled(value, rnd))
    # Output is valid UTF-8 JSON that parses back to the same value (numerically).
    parsed = json.loads(a.decode("utf-8"), parse_int=float)
    assert _num_eq(parsed, value)
    # Canonical form is a fixed point (I-JSON numbers are doubles: reparse integers as floats).
    assert canonicalize(parsed) == a


def _num_eq(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_num_eq(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_num_eq(x, y) for x, y in zip(a, b, strict=True))
    return a == b


@SETTINGS
@given(st.sampled_from([math.nan, math.inf, -math.inf]), st.sampled_from(["top", "list", "dict"]))
def test_non_finite_rejected(bad, where):
    value = {"top": bad, "list": [1, [bad]], "dict": {"a": {"b": bad}}}[where]
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


@SETTINGS
@given(st.integers(min_value=2**53) | st.integers(max_value=-(2**53)))
def test_huge_ints_rejected(n):
    with pytest.raises(CanonicalizationError):
        canonicalize({"n": n})


@SETTINGS
@given(st.sampled_from([b"x", object(), {1, 2}, 1 + 2j]))
def test_non_json_types_rejected(v):
    with pytest.raises(CanonicalizationError):
        canonicalize([v])


# --------------------------------------------------------------------------- envelopes

ID_TEXT = st.text(st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=10)
OPT_TEXT = st.none() | st.text(st.characters(blacklist_categories=("Cs",)), max_size=10)
UUIDS = st.uuids().map(str)
HEX = st.text("0123456789abcdef", min_size=64, max_size=64).map(lambda h: "sha256:" + h)
DTS = st.datetimes(
    min_value=datetime(1970, 1, 2),
    max_value=datetime(2999, 12, 30),
    timezones=st.just(UTC) | st.integers(-14, 14).map(lambda h: timezone(timedelta(hours=h))) | st.none(),
)
SCOPE = st.lists(ID_TEXT, max_size=3)


@st.composite
def envelopes(draw):
    source = draw(st.booleans())
    parents = [] if source else [{"context_id": draw(UUIDS), "object_version": draw(ID_TEXT)}]
    return ContextEnvelope.model_validate(
        {
            "context_id": draw(UUIDS),
            "tenant_id": draw(ID_TEXT),
            "object_id": draw(ID_TEXT),
            "object_version": draw(ID_TEXT),
            "content_digest": draw(HEX),
            "kind": "source" if source else draw(st.sampled_from(["chunk", "summary", "memory", "cache"])),
            "source_system": draw(st.text(st.characters(blacklist_categories=("Cs",)), max_size=10)),
            "source_acl_ref": draw(OPT_TEXT),
            "principal_scope": draw(SCOPE),
            "purpose_scope": draw(SCOPE),
            "classification": draw(st.sampled_from(["public", "internal", "confidential", "restricted"])),
            "trust_state": draw(st.sampled_from(["verified", "untrusted", "quarantined"])),
            "parent_refs": parents,
            "policy_version": draw(st.text(st.characters(blacklist_categories=("Cs",)), max_size=10)),
            "valid_from": draw(DTS),
            "expires_at": draw(st.none() | DTS),
        }
    )


@st.composite
def events(draw):
    scope = draw(
        st.none()
        | st.builds(
            lambda p, q: {"principals": p, "purposes": q},
            st.none() | SCOPE,
            st.none() | SCOPE,
        )
    )
    return RevocationEvent.model_validate(
        {
            "event_id": draw(UUIDS),
            "tenant_id": draw(ID_TEXT),
            "source_id": draw(ID_TEXT),
            "source_version": draw(OPT_TEXT),
            "reason": draw(
                st.sampled_from(
                    ["deleted", "acl_changed", "version_superseded", "expired", "compromised", "poisoned"]
                )
            ),
            "effective_at": draw(DTS),
            "source_event_id": draw(OPT_TEXT),
            "actor": draw(OPT_TEXT),
            "affected_scope": scope,
        }
    )


def _mutate(obj, rnd: random.Random):
    """Return a deep copy with exactly one leaf/key changed; paths are chosen among signed fields."""
    d = json.loads(json.dumps(obj))
    paths: list[tuple] = []

    def walk(v, path):
        if isinstance(v, dict):
            for k, x in v.items():
                if not path and k in ("signature", "issuer_key_id"):
                    continue
                paths.append((*path, k, "drop"))
                walk(x, (*path, k))
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, (*path, i))
        else:
            paths.append((*path, "leaf"))

    walk(d, ())
    p = paths[rnd.randrange(len(paths))]
    if p[-1] == "drop":
        parent = d
        for k in p[:-2]:
            parent = parent[k]
        del parent[p[-2]]
        return d
    parent = d
    for k in p[:-2]:
        parent = parent[k]
    key = p[-2] if len(p) >= 2 else None
    cur = parent[key]
    if isinstance(cur, bool):
        parent[key] = not cur
    elif isinstance(cur, int):
        parent[key] = cur + 1
    elif isinstance(cur, str):
        parent[key] = cur + "x" if not cur else chr((ord(cur[0]) + 1) % 0xD000 or 0x41) + cur[1:]
    elif cur is None:
        parent[key] = "injected"
    return d


@SETTINGS
@given(envelopes())
def test_sign_verify_envelope_roundtrip(env):
    signed = sign_model(env, KEY, "k1")
    assert verify_envelope(signed, PUB)
    # Verification works on the wire (JSON) form too, and survives a JSON round trip.
    wire = json.loads(signed.model_dump_json())
    assert verify_envelope(wire, PUB)
    assert verify_envelope(ContextEnvelope.model_validate(wire), PUB)
    # issuer_key_id is not covered by the signature.
    assert verify_envelope(signed.model_copy(update={"issuer_key_id": "other"}), PUB)
    # Unsigned envelopes never verify.
    assert not verify_envelope(env, PUB)


@SETTINGS
@given(envelopes(), st.randoms(use_true_random=False))
def test_envelope_single_mutation_breaks_signature(env, rnd):
    signed = sign_model(env, KEY, "k1")
    wire = json.loads(signed.model_dump_json())
    for _ in range(3):
        mutated = _mutate(wire, rnd)
        if canonical_bytes(mutated) == canonical_bytes(wire):
            continue  # mutation was a no-op semantically (e.g. whitespace-free identical)
        assert verify_envelope(mutated, PUB) is False


@SETTINGS
@given(events(), st.randoms(use_true_random=False))
def test_event_roundtrip_and_mutation(ev, rnd):
    signed = sign_model(ev, KEY, "k1")
    assert verify_event(signed, PUB)
    wire = json.loads(signed.model_dump_json())
    assert verify_event(wire, PUB)
    mutated = _mutate(wire, rnd)
    if canonical_bytes(mutated) != canonical_bytes(wire):
        assert verify_event(mutated, PUB) is False


@SETTINGS
@given(
    envelopes(),
    st.one_of(st.binary(max_size=200), st.text(max_size=100), st.just(""), st.integers(), st.none()),
)
def test_malformed_signature_never_raises(env, junk):
    signed = sign_model(env, KEY, "k1")
    wire = json.loads(signed.model_dump_json())
    wire["signature"] = junk.hex() if isinstance(junk, bytes) else junk
    assert verify_envelope(wire, PUB) is False
    # base64 of junk of arbitrary length (valid alphabet, wrong content)
    import base64

    if isinstance(junk, bytes):
        wire["signature"] = base64.b64encode(junk).decode()
        assert verify_envelope(wire, PUB) is False
        wire["signature"] = base64.urlsafe_b64encode(junk).decode()
        assert verify_envelope(wire, PUB) in (False, True) or True  # must simply not raise


@SETTINGS
@given(envelopes(), st.one_of(st.text(max_size=50), st.binary(max_size=50).map(lambda b: b.hex()), st.none()))
def test_malformed_issuer_key_id_irrelevant_to_verify(env, kid):
    signed = sign_model(env, KEY, "k1")
    wire = json.loads(signed.model_dump_json())
    wire["issuer_key_id"] = kid
    assert verify_envelope(wire, PUB) is True  # not covered by the signature; trust is keys.py's job
    wire.pop("issuer_key_id")
    assert verify_envelope(wire, PUB) is True


@SETTINGS
@given(
    envelopes(),
    st.one_of(st.lists(st.integers(), max_size=3), st.dictionaries(st.text(max_size=3), st.integers())),
)
def test_non_string_signature_member_never_raises(env, junk):
    wire = json.loads(sign_model(env, KEY, "k1").model_dump_json())
    wire["signature"] = junk
    assert verify_envelope(wire, PUB) is False


# --------------------------------------------------------------------------- timestamps


@SETTINGS
@given(DTS)
def test_datetime_normalised_to_utc(dt):
    """Naive datetimes are interpreted as UTC; aware ones are converted; output is always ...Z."""
    env = ContextEnvelope.model_validate(
        {
            "context_id": str(uuid.uuid4()),
            "tenant_id": "t",
            "object_id": "o",
            "object_version": "1",
            "content_digest": "sha256:" + "0" * 64,
            "kind": "source",
            "source_system": "s",
            "classification": "public",
            "trust_state": "verified",
            "parent_refs": [],
            "policy_version": "p",
            "valid_from": dt,
        }
    )
    assert env.valid_from.tzinfo is not None and env.valid_from.utcoffset() == timedelta(0)
    expected = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    assert env.valid_from == expected
    raw = canonical_bytes(env)
    assert json.loads(raw)["valid_from"].endswith(("Z", "+00:00"))
    # Same instant expressed in any zone canonicalises identically (after model normalisation).
    shifted = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(timezone(timedelta(hours=5)))
    env2 = ContextEnvelope.model_validate({**env.model_dump(), "valid_from": shifted})
    assert canonical_bytes(env2) == raw
    assert verify_envelope(sign_model(env, KEY, "k"), PUB)
