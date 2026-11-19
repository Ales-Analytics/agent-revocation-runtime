"""Fuzz the HTTP surface: malformed bodies/headers must yield 4xx, never 5xx, and never kill the app."""

from __future__ import annotations

import copy
import json
import unicodedata
import uuid
from urllib.parse import quote

import pytest
from ales_sdk import new_derivative, new_source
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from server_helpers import ALL, P

SETTINGS = settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)

TEXT = st.text(max_size=20)
JSON_VALUE = st.recursive(
    # Non-finite floats are pinned separately (known 500, see test_known_bug_*).
    st.none()
    | st.booleans()
    | st.integers(-(2**70), 2**70)
    | st.floats(allow_nan=False, allow_infinity=False)
    | TEXT,
    lambda kids: st.lists(kids, max_size=4) | st.dictionaries(TEXT, kids, max_size=4),
    max_leaves=12,
)
JSON_OBJECT = st.dictionaries(TEXT, JSON_VALUE, max_size=6)

ENDPOINTS = ["/v1/authorize", "/v1/sources", "/v1/derivations", "/v1/revocations", "/v1/verify"]


def _dumps(v) -> bytes:
    # allow_nan=True: NaN/Infinity literals are legal for Python's parser and must not crash the server.
    return json.dumps(v, allow_nan=True).encode("utf-8", "surrogatepass")


def _post(client, path: str, body: bytes, **kw):
    return client.post(path, content=body, headers={"Content-Type": "application/json"}, **kw)


def _alive(client) -> None:
    assert client.get("/v1/healthz", headers={}).json() == {"status": "ok"}


@SETTINGS
@given(st.sampled_from(ENDPOINTS), JSON_VALUE)
def test_arbitrary_json_bodies_are_4xx(make_client, path, body):
    client = _SHARED.get("c") or _SHARED.setdefault("c", make_client())
    if path == "/v1/verify" and isinstance(body, dict) and set(body) <= {"tenant_id", "adapter", "mode"}:
        assume(False)  # may legitimately be accepted
    r = _post(client, path, _dumps(body))
    assert 400 <= r.status_code < 500, (path, body, r.status_code, r.text)
    _alive(client)


_SHARED: dict = {}


@pytest.fixture(autouse=True)
def _reset_shared():
    _SHARED.clear()
    yield
    _SHARED.clear()


@SETTINGS
@given(st.sampled_from(ENDPOINTS), st.binary(max_size=300))
def test_arbitrary_bytes_bodies_are_4xx(make_client, path, body):
    client = _SHARED.get("c") or _SHARED.setdefault("c", make_client())
    r = _post(client, path, body)
    assert 400 <= r.status_code < 500, (path, body, r.status_code, r.text)
    _alive(client)


@SETTINGS
@given(
    st.sampled_from(["application/json", "text/plain", "application/x-www-form-urlencoded", "", "x/y;z"]),
    st.binary(max_size=100),
)
def test_content_type_and_empty_bodies(make_client, ctype, body):
    client = _SHARED.get("c") or _SHARED.setdefault("c", make_client())
    if ctype != "application/json":
        try:
            body.decode("utf-8")
        except UnicodeDecodeError:
            assume(False)  # known server bug, pinned separately below
    for path in ENDPOINTS:
        headers = {"Content-Type": ctype} if ctype else {}
        r = client.post(path, content=body, headers=headers)
        assert r.status_code < 500 and r.status_code != 200 or path == "/v1/verify", (
            path,
            r.status_code,
            r.text,
        )
    _alive(client)


WRONG = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-(2**70), 2**70),
    st.floats(allow_nan=False, allow_infinity=False),
    TEXT,
    st.lists(st.integers(), max_size=3),
    st.dictionaries(TEXT, st.integers(), max_size=2),
    st.just(""),
    st.just("\x00"),
    st.just("a" * 5000),
)


def _valid_bodies():
    cid = str(uuid.uuid4())
    src = new_source("t1", "doc", b"x", "kb")
    chunk = new_derivative("chunk", [src], "t1", "c", b"c")
    return {
        "/v1/authorize": {
            "tenant_id": "t1",
            "principal": P,
            "purpose": "rag",
            "objects": [{"context_id": cid, "version": "1"}],
            "tools": ["t"],
            "risk": "low",
            "agent_id": "a",
            "session_id": "s",
        },
        "/v1/sources": src,
        "/v1/derivations": chunk,
        "/v1/revocations": {
            "tenant_id": "t1",
            "source_id": cid,
            "reason": "deleted",
            "affected_scope": {"principals": ["alice"], "purposes": ["rag"]},
            "effective_at": "2030-01-01T00:00:00Z",
        },
    }


@SETTINGS
@given(st.sampled_from(sorted(_valid_bodies())), st.data())
def test_near_valid_mutations_never_500(make_client, path, data):
    client = _SHARED.get("c") or _SHARED.setdefault("c", make_client())
    # Deep copy: the valid bodies embed shared helper dicts (e.g. P); in-place mutation would
    # poison every later test in the process.
    body = copy.deepcopy(_valid_bodies()[path])
    # Mutate 1-2 fields, optionally one level down.
    for _ in range(data.draw(st.integers(1, 2))):
        key = data.draw(st.sampled_from(sorted(body)))
        if isinstance(body[key], dict) and body[key] and data.draw(st.booleans()):
            sub = data.draw(st.sampled_from(sorted(body[key])))
            body[key][sub] = data.draw(WRONG)
        elif data.draw(st.integers(0, 4)) == 0:
            del body[key]
        else:
            body[key] = data.draw(WRONG)
    r = _post(client, path, _dumps(body))
    assert r.status_code < 500, (path, body, r.status_code, r.text)
    _alive(client)


@SETTINGS
@given(st.lists(st.integers(0, 3), min_size=0, max_size=3000))
def test_deep_and_wide_json_is_bounded(make_client, shape):
    client = _SHARED.get("c") or _SHARED.setdefault("c", make_client())
    depth = len(shape)
    nested = "[" * depth + "]" * depth if depth else "[]"
    for path in ("/v1/authorize", "/v1/revocations"):
        r = _post(client, path, nested.encode())
        assert 400 <= r.status_code < 500
    r = _post(client, "/v1/authorize", ('{"objects":' + nested + "}").encode())
    assert 400 <= r.status_code < 500
    _alive(client)


def test_known_bug_non_utf8_body_non_json_content_type(make_client):
    client = make_client()
    r = client.post("/v1/authorize", content=bytes([0x80]), headers={"Content-Type": "text/plain"})
    assert 400 <= r.status_code < 500


@pytest.mark.parametrize(
    "raw", [b"Infinity", b"-Infinity", b"NaN", b'{"tenant_id": Infinity}', b'{"objects":[NaN]}']
)
def test_known_bug_nonfinite_json_literal(make_client, raw):
    client = make_client()
    for path in ENDPOINTS:
        r = _post(client, path, raw)
        assert 400 <= r.status_code < 500, (path, r.status_code)


def test_oversized_body_is_413(make_client):
    client = make_client(max_body=2048)
    r = _post(client, "/v1/authorize", b'{"x":"' + b"a" * 5000 + b'"}')
    assert r.status_code == 413
    _alive(client)


HDR_CHARS = st.characters(min_codepoint=0x20, max_codepoint=0x7E) | st.sampled_from(["\t", "\x7f", "é", " "])
HDR = st.text(HDR_CHARS, max_size=60)


def _send(client, headers: dict, method="post", path="/v1/authorize"):
    body = {
        "tenant_id": "t1",
        "principal": P,
        "purpose": "rag",
        "objects": [{"context_id": str(uuid.uuid4())}],
    }
    try:
        h = {k: v for k, v in headers.items()}
        if method == "post":
            return client.post(path, json=body, headers=h)
        return client.get(path, headers=h)
    except (UnicodeEncodeError, ValueError):  # client-side refusal to even encode the header
        return None


@SETTINGS
@given(HDR, st.booleans())
def test_authorization_header_fuzz(make_client, value, with_scheme):
    client = _SHARED.get("c") or _SHARED.setdefault("c", make_client())
    # Remove the default valid Authorization so we only send fuzz.
    client.headers.pop("authorization", None)
    hv = f"Bearer {value}" if with_scheme else value
    r = _send(client, {"Authorization": hv})
    assume(r is not None)
    assert r.status_code in (401, 403), (hv, r.status_code, r.text)
    _alive(client)


@SETTINGS
@given(HDR)
def test_tenant_header_fuzz_with_valid_token(make_client, value):
    client = _SHARED.get("c") or _SHARED.setdefault("c", make_client())
    r = _send(client, {"X-Tenant-Id": value})
    assume(r is not None)
    if value == "t1":
        assert r.status_code < 500
    else:
        assert r.status_code in (401, 403), (value, r.status_code, r.text)
    _alive(client)


@SETTINGS
@given(HDR, HDR)
def test_header_pair_fuzz_never_500(make_client, auth, tenant):
    client = _SHARED.get("c") or _SHARED.setdefault("c", make_client())
    client.headers.pop("authorization", None)
    r = _send(client, {"Authorization": auth, "X-Tenant-Id": tenant}, method="get", path="/v1/snapshot")
    assume(r is not None)
    assert r.status_code in (401, 403), (auth, tenant, r.status_code)


@SETTINGS
@given(TEXT, TEXT)
def test_query_param_tenant_fuzz(make_client, tenant, ctx_id):
    client = _SHARED.get("c") or _SHARED.setdefault("c", make_client())
    r = client.get("/v1/lineage/" + quote(ctx_id, safe=""), params={"tenant_id": tenant})
    assert r.status_code < 500
    if tenant != "t1":
        assert r.status_code in (403, 404, 422)
    _alive(client)


# ---- unicode round trips (tenants are bound to credentials, so register one token per tenant) ----

NFC = unicodedata.normalize("NFC", "café")
NFD = unicodedata.normalize("NFD", "café")
UNICODE_TENANTS = {
    "nfc": NFC,
    "nfd": NFD,
    "astral": "t-\U0001f600\U00010348",
    "rtl-zw": "שלום\u200b-t",
    "space": "tenant with spaces",
}
UTOKENS = {
    f"tok-{k}": {"tenant_id": v, "roles": ALL, "subject": f"svc-{k}"} for k, v in UNICODE_TENANTS.items()
}

UNI = st.text(
    st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"), min_size=1, max_size=12
)


@SETTINGS
@given(st.sampled_from(sorted(UNICODE_TENANTS)), UNI, UNI, UNI, UNI)
def test_unicode_ids_roundtrip_exactly(make_client, tkey, object_id, principal, purpose, other):
    client = _SHARED.get("u") or _SHARED.setdefault("u", make_client(tokens=UTOKENS))
    tenant = UNICODE_TENANTS[tkey]
    auth = {"Authorization": f"Bearer tok-{tkey}"}
    src = new_source(
        tenant,
        object_id,
        b"payload-" + uuid.uuid4().bytes,
        "sys",
        principal_scope=[principal],
        purpose_scope=[purpose],
    )
    r = client.post("/v1/sources", json=src, headers=auth)
    assert r.status_code == 200, r.text
    assert r.json()["context_id"] == src["context_id"]

    def authz(p, q):
        return client.post(
            "/v1/authorize",
            headers=auth,
            json={
                "tenant_id": tenant,
                "principal": {"type": "user", "id": p},
                "purpose": q,
                "objects": [{"context_id": src["context_id"]}],
            },
        )

    ok = authz(principal, purpose)
    assert ok.status_code == 200 and ok.json()["decision"] == "ALLOW", ok.text
    # No silent normalisation: any different string (incl. NFC/NFD variants) is out of scope.
    for variant in {unicodedata.normalize(f, principal) for f in ("NFC", "NFD", "NFKC", "NFKD")} - {
        principal
    }:
        d = authz(variant, purpose)
        assert d.status_code == 200 and d.json()["decision"] == "DENY", (principal, variant)
    for variant in {unicodedata.normalize(f, purpose) for f in ("NFC", "NFD", "NFKC", "NFKD")} - {purpose}:
        d = authz(principal, variant)
        assert d.status_code == 200 and d.json()["decision"] == "DENY", (purpose, variant)
    if other != principal:
        assert authz(other, purpose).json()["decision"] == "DENY"
    # The lineage view is tenant-scoped by exact string.
    ln = client.get(f"/v1/lineage/{src['context_id']}", headers=auth, params={"tenant_id": tenant})
    assert ln.status_code == 200
    # NFC- and NFD-named tenants are distinct tenants: the other cannot see this object.
    if tkey in ("nfc", "nfd"):
        other_key = "nfd" if tkey == "nfc" else "nfc"
        x = client.get(
            f"/v1/lineage/{src['context_id']}",
            headers={"Authorization": f"Bearer tok-{other_key}"},
            params={"tenant_id": UNICODE_TENANTS[other_key]},
        )
        assert x.status_code == 404
