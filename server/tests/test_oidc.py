"""OIDC/JWT bearer authentication: RS256 + ES256, strict claim handling, no registry fall-through."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from ales_server import create_app
from ales_server.config import ConfigError, JwksSettings
from ales_server.oidc import OidcError, OidcVerifier, RemoteJwks
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient
from server_helpers import TOKENS, FakeClock, bearer

ISS = "https://idp.example.com/"
AUD = "ales-invariant"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _int(n: int) -> str:
    return b64u(n.to_bytes((n.bit_length() + 7) // 8, "big"))


RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())


def rsa_jwk(key, kid):
    n = key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _int(n.n), "e": _int(n.e)}


def ec_jwk(key, kid):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "kid": kid, "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}


JWKS = {"keys": [rsa_jwk(RSA_KEY, "rk1"), ec_jwk(EC_KEY, "ek1")]}
MAPPING = {"tenant_id": "org", "subject": "sub", "roles": "ales_roles"}


def config(**over):
    cfg = {"issuer": ISS, "audience": AUD, "jwks": JWKS, "claim_mapping": MAPPING}
    cfg.update(over)
    return json.dumps(cfg)


def claims(**over):
    c = {"iss": ISS, "aud": AUD, "sub": "alice@idp", "org": "t1", "ales_roles": ["read"], "exp": time.time() + 600}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def mint(payload=None, *, alg="RS256", kid="rk1", key=None, header=None):
    h = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        h["kid"] = kid
    h.update(header or {})
    signing = f"{b64u(json.dumps(h).encode())}.{b64u(json.dumps(payload if payload is not None else claims()).encode())}"
    if alg == "RS256":
        sig = (key or RSA_KEY).sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256":
        r, s = decode_dss_signature((key or EC_KEY).sign(signing.encode(), ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    elif alg == "HS256":
        sig = hmac.new(b"secret", signing.encode(), hashlib.sha256).digest()
    else:  # none
        sig = b""
    return f"{signing}.{b64u(sig)}"


@pytest.fixture
def oidc_client():
    app = create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_OIDC_CONFIG": config()})
    with TestClient(app) as tc:
        yield tc


def get(tc, token, path="/v1/workloads", **kw):
    return tc.get(path, headers=bearer(token), **kw)


def assert_401(r):
    assert r.status_code == 401, r.text
    assert r.json() == {"detail": "missing or invalid credentials"}
    assert r.headers["www-authenticate"] == "Bearer"


# ------------------------------------------------------------------------------------------ happy paths
def test_valid_rs256_token_maps_tenant_subject_roles(oidc_client):
    tok = mint(claims(ales_roles=["read", "admin"], org="tenant-x", sub="bob"))
    assert get(oidc_client, tok).status_code == 200
    # the identity is the token's: tenant-x, admin role -> create a workload, then audit shows the subject
    r = oidc_client.post(
        "/v1/workloads", json={"workload_id": "w", "kind": "agent", "display_name": "w"}, headers=bearer(tok)
    )
    assert r.status_code == 201
    assert get(oidc_client, mint(claims(org="t1")), "/v1/workloads").json() == {"workloads": []}  # tenant t1 sees nothing
    assert len(get(oidc_client, tok).json()["workloads"]) == 1
    from ales_core import AuditLog
    from sqlalchemy import select

    with oidc_client.app.state.session_factory() as s:
        rec = s.scalars(select(AuditLog).where(AuditLog.tenant_id == "tenant-x", AuditLog.action == "workload.register")).one()
    assert rec.actor == "bob"


def test_valid_es256_token(oidc_client):
    assert get(oidc_client, mint(alg="ES256", kid="ek1")).status_code == 200


def test_roles_are_enforced_from_the_token(oidc_client):
    tok = mint(claims(ales_roles=["read"]))
    r = oidc_client.post(
        "/v1/workloads", json={"workload_id": "w", "kind": "agent", "display_name": "w"}, headers=bearer(tok)
    )
    assert r.status_code == 403 and r.json() == {"detail": "role 'admin' required"}


def test_aud_list_and_nbf_exp_skew(oidc_client):
    assert get(oidc_client, mint(claims(aud=["other", AUD]))).status_code == 200
    assert get(oidc_client, mint(claims(exp=time.time() - 30))).status_code == 200  # within 60 s skew
    assert get(oidc_client, mint(claims(nbf=time.time() + 30))).status_code == 200
    assert get(oidc_client, mint(claims(iat=time.time() + 9999))).status_code == 200  # iat is not enforced


def test_tenant_header_mismatch_still_403(oidc_client):
    r = oidc_client.get("/v1/workloads", headers={**bearer(mint()), "X-Tenant-Id": "t2"})
    assert r.status_code == 403


def test_static_roles_mapping():
    cfg = config(claim_mapping={"tenant_id": "org", "subject": "sub", "roles": {"static": ["read"]}})
    app = create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_OIDC_CONFIG": cfg})
    with TestClient(app) as tc:
        assert get(tc, mint(claims(ales_roles=None))).status_code == 200
        r = tc.post("/v1/workloads", json={}, headers=bearer(mint(claims(ales_roles=None))))
        assert r.status_code == 403  # fixed to read, the token cannot widen it


# ---------------------------------------------------------------------------------------- rejections
def _tamper_sig(tok):
    h, p, s = tok.split(".")
    return f"{h}.{p}.{s[:-4]}AAAA"


def _swap_payload(tok, **over):
    h, _, s = tok.split(".")
    return f"{h}.{b64u(json.dumps(claims(**over)).encode())}.{s}"


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda: _tamper_sig(mint()), id="tampered-signature"),
        pytest.param(lambda: _swap_payload(mint(), ales_roles=["admin"], org="t2"), id="tampered-payload"),
        pytest.param(lambda: mint(claims(iss="https://evil.example.com/")), id="wrong-iss"),
        pytest.param(lambda: mint(claims(iss=ISS.rstrip("/"))), id="iss-not-exact"),
        pytest.param(lambda: mint(claims(aud="someone-else")), id="wrong-aud"),
        pytest.param(lambda: mint(claims(aud=["a", "b"])), id="aud-list-without-audience"),
        pytest.param(lambda: mint(claims(aud=None)), id="missing-aud"),
        pytest.param(lambda: mint(claims(exp=time.time() - 3600)), id="expired"),
        pytest.param(lambda: mint(claims(exp=None)), id="no-exp"),
        pytest.param(lambda: mint(claims(exp="never")), id="string-exp"),
        pytest.param(lambda: mint(claims(nbf=time.time() + 3600)), id="not-yet-valid"),
        pytest.param(lambda: mint(alg="none"), id="alg-none"),
        pytest.param(lambda: mint(alg="HS256"), id="alg-hs256"),
        pytest.param(lambda: mint(kid="ghost"), id="unknown-kid"),
        pytest.param(lambda: mint(kid=None), id="no-kid-with-several-keys"),
        pytest.param(lambda: mint(key=OTHER_RSA), id="signed-by-other-key"),
        pytest.param(lambda: mint(alg="ES256", kid="rk1"), id="alg-key-confusion-es-vs-rsa"),
        pytest.param(lambda: mint(alg="RS256", kid="ek1"), id="alg-key-confusion-rs-vs-ec"),
        pytest.param(lambda: mint(header={"crit": ["exp"]}), id="crit-header"),
        pytest.param(lambda: mint(claims(org=None)), id="missing-tenant-claim"),
        pytest.param(lambda: mint(claims(sub=None)), id="missing-subject-claim"),
        pytest.param(lambda: mint(claims(ales_roles=None)), id="missing-roles-claim"),
        pytest.param(lambda: mint(claims(ales_roles=[])), id="empty-roles"),
        pytest.param(lambda: mint(claims(ales_roles="admin")), id="roles-not-a-list"),
        pytest.param(lambda: mint(claims(ales_roles=["read", "superuser"])), id="unknown-role"),
        pytest.param(lambda: mint(claims(org="")), id="empty-tenant"),
        pytest.param(lambda: mint(claims(org=7)), id="non-string-tenant"),
        pytest.param(lambda: mint(claims(org="t1:verify")), id="verify-suffix-tenant"),
        pytest.param(lambda: mint(claims(tenant_id="t1", org=None)), id="unmapped-claim-name-ignored"),
        pytest.param(lambda: "a.b.c", id="garbage"),
        pytest.param(lambda: mint().rsplit(".", 1)[0] + ".", id="empty-signature"),
    ],
)
def test_invalid_tokens_are_401(oidc_client, make):
    assert_401(get(oidc_client, make()))


def test_unmapped_claims_never_used(oidc_client):
    """`tenant_id`/`roles`/`scope` claims that are not in claim_mapping have no effect."""
    tok = mint(claims(tenant_id="t2", roles=["admin"], scope="admin"))
    assert get(oidc_client, tok).status_code == 200
    assert oidc_client.post("/v1/policies", json={}, headers=bearer(tok)).status_code == 403  # still only `read`


def test_jwt_shaped_token_never_matches_registry():
    shaped = "aaa.bbb.ccc"
    tokens = {**TOKENS, shaped: {"tenant_id": "t1", "roles": ["read"], "subject": "static"}}
    on = create_app("sqlite://", tokens=tokens, outbox_interval=0, env={"ALES_OIDC_CONFIG": config()})
    with TestClient(on) as tc:
        assert_401(get(tc, shaped))  # JWT-shaped -> JWT path -> invalid -> 401, registry never consulted
        assert get(tc, "tok-t1-all").status_code == 200  # opaque tokens still use the registry
    off = create_app("sqlite://", tokens=tokens, outbox_interval=0, env={})
    with TestClient(off) as tc:
        assert get(tc, shaped).status_code == 200  # without OIDC nothing changes


def test_valid_jwt_cannot_fall_back_to_registry_roles(oidc_client):
    # a bad JWT is a 401 even if its subject/tenant would match a registry entry
    assert_401(get(oidc_client, mint(claims(exp=time.time() - 9999, sub="svc-t1"))))


def test_oidc_only_mode_rejects_opaque_tokens():
    app = create_app("sqlite://", outbox_interval=0, env={"ALES_OIDC_CONFIG": config()})
    with TestClient(app) as tc:
        assert get(tc, mint()).status_code == 200
        assert_401(get(tc, "tok-t1-all"))
        assert tc.get("/v1/workloads").status_code == 401
        assert tc.get("/v1/healthz").status_code == 200


def test_dev_anonymous_is_disabled_when_oidc_configured():
    app = create_app(
        "sqlite://", outbox_interval=0, env={"ALES_OIDC_CONFIG": config(), "ALES_DEV_ALLOW_ANONYMOUS": "1"}
    )
    with TestClient(app) as tc:
        assert tc.get("/v1/workloads", headers={"X-Tenant-Id": "t1"}).status_code == 401


# ------------------------------------------------------------------------------------------- config
def test_jwks_file_config(tmp_path):
    f = tmp_path / "jwks.json"
    f.write_text(json.dumps(JWKS), encoding="utf-8")
    cfg = json.dumps({"issuer": ISS, "audience": AUD, "jwks_file": str(f), "claim_mapping": MAPPING})
    app = create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_OIDC_CONFIG": cfg})
    with TestClient(app) as tc:
        assert get(tc, mint()).status_code == 200


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "[]",
        json.dumps({"issuer": ISS}),
        json.dumps({"issuer": ISS, "audience": AUD, "jwks": JWKS}),  # no claim_mapping
        json.dumps({"issuer": ISS, "audience": AUD, "jwks": JWKS, "jwks_file": "x", "claim_mapping": MAPPING}),
        json.dumps({"issuer": ISS, "audience": AUD, "jwks": {"keys": []}, "claim_mapping": MAPPING}),
        json.dumps({"issuer": ISS, "audience": AUD, "jwks": {"keys": [{"kty": "oct", "k": "AA"}]}, "claim_mapping": MAPPING}),
        json.dumps({"issuer": ISS, "audience": AUD, "jwks_file": "/no/such/file", "claim_mapping": MAPPING}),
        json.dumps(
            {"issuer": ISS, "audience": AUD, "jwks": JWKS, "claim_mapping": {"tenant_id": "o", "subject": "s", "roles": {"static": ["root"]}}}
        ),
        json.dumps({"issuer": ISS, "audience": AUD, "jwks": JWKS, "claim_mapping": {"tenant_id": "o", "subject": "s"}}),
        json.dumps({"issuer": ISS, "audience": AUD, "jwks": {"keys": [rsa_jwk(RSA_KEY, "k"), rsa_jwk(OTHER_RSA, "k")]}, "claim_mapping": MAPPING}),
    ],
)
def test_bad_oidc_config_is_a_startup_error(raw):
    with pytest.raises(ConfigError):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_OIDC_CONFIG": raw})


def test_small_rsa_key_refused():
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(ConfigError):
        OidcVerifier.from_config(
            json.dumps({"issuer": ISS, "audience": AUD, "jwks": {"keys": [rsa_jwk(small, "s")]}, "claim_mapping": MAPPING}),
            frozenset({"read"}),
        )


def test_injected_clock_controls_expiry():
    v = OidcVerifier.from_config(config(), frozenset({"read", "admin"}), clock=lambda: 1_000_000.0)
    assert v.verify(mint(claims(exp=1_000_100))) == ("alice@idp", "t1", frozenset({"read"}))
    from ales_server.oidc import OidcError

    with pytest.raises(OidcError):
        v.verify(mint(claims(exp=1_000_000 - 61)))


# ============================================================================ live jwks_uri fetching
WEAK_RSA = rsa.generate_private_key(public_exponent=65537, key_size=1024)


class JwksServer:
    """Threaded loopback JWKS endpoint. ``count`` = requests served; ``status``/``body`` are switchable."""

    def __init__(self):
        outer = self
        self.count, self.status, self.body = 0, 200, json.dumps({"keys": [rsa_jwk(RSA_KEY, "rk1")]}).encode()
        self.lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                with outer.lock:
                    outer.count += 1
                    status, body = outer.status, outer.body
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/jwks.json"
        self.thread = threading.Thread(target=lambda: self.httpd.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()

    def serve(self, *jwks):
        self.body = json.dumps({"keys": list(jwks)}).encode()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def jwks_server():
    srv = JwksServer()
    yield srv
    srv.close()


def uri_config(url, **over):
    cfg = {"issuer": ISS, "audience": AUD, "jwks_uri": url, "claim_mapping": MAPPING}
    cfg.update(over)
    return json.dumps(cfg)


def remote_verifier(srv, clock=None, **settings):
    clock = clock or FakeClock()
    s = JwksSettings(**({"ttl": 300.0, "min_refresh": 30.0, "max_stale": 3600.0} | settings))
    return OidcVerifier.from_config(uri_config(srv.url), frozenset(ROLES), jwks_settings=s, jwks_clock=clock), clock


ROLES = {"ingest", "revoke", "read", "admin"}


def test_jwks_uri_fetch_verify_and_cache(jwks_server):
    v, clock = remote_verifier(jwks_server)
    assert jwks_server.count == 0  # lazy: nothing fetched at construction
    assert v.verify(mint())[0] == "alice@idp"
    assert jwks_server.count == 1
    for _ in range(5):
        v.verify(mint())
    assert jwks_server.count == 1  # served from cache within the TTL
    clock.advance(299)
    v.verify(mint())
    assert jwks_server.count == 1
    clock.advance(2)  # TTL (300) elapsed
    v.verify(mint())
    assert jwks_server.count == 2


def test_jwks_uri_rotation_after_refetch(jwks_server):
    v, clock = remote_verifier(jwks_server)
    v.verify(mint())  # fetch #1: only rk1
    jwks_server.serve(rsa_jwk(RSA_KEY, "rk1"), rsa_jwk(OTHER_RSA, "rk2"))
    new_token = mint(kid="rk2", key=OTHER_RSA)
    with pytest.raises(OidcError, match="unknown kid"):  # inside the throttle window: no refetch yet
        v.verify(new_token)
    assert jwks_server.count == 1
    clock.advance(31)
    assert v.verify(new_token)[0] == "alice@idp"  # unknown kid triggered exactly one refetch
    assert jwks_server.count == 2
    v.verify(mint())  # the old key still verifies


def test_jwks_uri_unknown_kid_refetch_is_throttled(jwks_server):
    v, clock = remote_verifier(jwks_server)
    v.verify(mint())
    junk = mint(kid="nope")
    for _ in range(25):
        with pytest.raises(OidcError):
            v.verify(junk)
    assert jwks_server.count == 1  # a flood of unknown kids cannot stampede the IdP
    clock.advance(31)
    for _ in range(25):
        with pytest.raises(OidcError):
            v.verify(junk)
    assert jwks_server.count == 2  # one refetch per min-refresh window


def test_jwks_uri_failure_with_cache_keeps_serving(jwks_server, caplog):
    v, clock = remote_verifier(jwks_server)
    v.verify(mint())
    jwks_server.status = 503
    clock.advance(301)  # TTL elapsed -> refresh attempt -> fails
    with caplog.at_level(logging.WARNING, logger="ales.server.oidc"):
        assert v.verify(mint())[0] == "alice@idp"  # stale cache still serves
        for _ in range(5):
            v.verify(mint())
    assert jwks_server.count == 2  # one failed attempt, then throttled
    assert len([r for r in caplog.records if "JWKS fetch failed" in r.message]) == 1  # logged once per streak
    clock.advance(31)
    v.verify(mint())
    assert jwks_server.count == 3  # retry after min-refresh, still failing, still serving
    jwks_server.status = 200
    clock.advance(31)
    v.verify(mint())
    assert jwks_server.count == 4  # recovered
    clock.advance(4000)  # failure streak was cleared, so the max-stale clock restarted
    v.verify(mint())


def test_jwks_uri_max_stale_exceeded_fails_closed(jwks_server, caplog):
    v, clock = remote_verifier(jwks_server, max_stale=600.0)
    v.verify(mint())
    jwks_server.status = 500
    clock.advance(301)
    v.verify(mint())  # failure streak starts here (t0)
    clock.advance(500)
    v.verify(mint())  # 500 s into the streak: still within max_stale
    clock.advance(101)
    with caplog.at_level(logging.ERROR, logger="ales.server.oidc"):
        with pytest.raises(OidcError, match="stale"):
            v.verify(mint())  # 601 s > 600
        with pytest.raises(OidcError, match="stale"):
            v.verify(mint())
    assert len([r for r in caplog.records if "MAX_STALE" in r.message]) == 1
    jwks_server.status = 200  # recovery lifts the block
    clock.advance(31)
    assert v.verify(mint())[0] == "alice@idp"


def test_jwks_uri_empty_cache_failure_is_unauthorized(jwks_server):
    jwks_server.status = 500
    v, clock = remote_verifier(jwks_server)
    for _ in range(4):
        with pytest.raises(OidcError, match="unavailable"):
            v.verify(mint())
    assert jwks_server.count == 1  # retries are throttled too
    clock.advance(31)
    with pytest.raises(OidcError):
        v.verify(mint())
    assert jwks_server.count == 2
    jwks_server.status = 200
    clock.advance(31)
    assert v.verify(mint())[0] == "alice@idp"


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", b'{"keys": "x"}', b'{"keys": []}', None],
)
def test_jwks_uri_bad_documents_are_failures(jwks_server, body):
    if body is None:  # RSA key below the 2048-bit floor: same constraint as a static JWKS
        jwks_server.serve(rsa_jwk(WEAK_RSA, "rk1"))
    else:
        jwks_server.body = body
    v, _ = remote_verifier(jwks_server)
    with pytest.raises(OidcError):
        v.verify(mint())


def test_jwks_uri_same_key_constraints_as_static(jwks_server):
    jwks_server.serve(rsa_jwk(RSA_KEY, "dup"), rsa_jwk(OTHER_RSA, "dup"))  # duplicate kid
    v, _ = remote_verifier(jwks_server)
    with pytest.raises(OidcError):
        v.verify(mint(kid="dup"))
    jwks_server.serve(ec_jwk(EC_KEY, "ek1"))  # ES256 works; an RS256 token against an EC key does not
    v, _ = remote_verifier(jwks_server)
    assert v.verify(mint(alg="ES256", kid="ek1"))[0] == "alice@idp"
    with pytest.raises(OidcError, match="algorithm"):
        v.verify(mint(alg="RS256", kid="ek1"))


def test_jwks_uri_oversized_response_rejected(jwks_server):
    jwks_server.body = b'{"keys": [], "pad": "' + b"x" * 1_100_000 + b'"}'
    v, _ = remote_verifier(jwks_server)
    with pytest.raises(OidcError):
        v.verify(mint())


def test_jwks_uri_concurrent_cold_start_fetches_once(jwks_server):
    v, _ = remote_verifier(jwks_server)
    errors, results = [], []

    def work():
        try:
            results.append(v.verify(mint())[0])
        except BaseException as exc:  # noqa: BLE001  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(16)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors and results == ["alice@idp"] * 16
    assert jwks_server.count == 1


@pytest.mark.parametrize(
    "uri",
    [
        "http://idp.example.com/jwks.json",
        "http://127.0.0.2/jwks.json",
        "http://localhost.evil.com/jwks.json",
        "ftp://idp.example.com/jwks.json",
        "file:///etc/jwks.json",
        "//idp.example.com/jwks.json",
        "idp.example.com/jwks.json",
        "https://user:pw@idp.example.com/jwks.json",
        "https:///jwks.json",
        "",
        5,
    ],
)
def test_jwks_uri_scheme_enforcement(uri):
    with pytest.raises(ConfigError):
        OidcVerifier.from_config(uri_config(uri), frozenset(ROLES))


@pytest.mark.parametrize(
    "uri", ["https://idp.example.com/.well-known/jwks.json", "http://127.0.0.1:9/jwks.json", "http://localhost/jwks.json"]
)
def test_jwks_uri_accepted_schemes(uri):
    assert OidcVerifier.from_config(uri_config(uri), frozenset(ROLES)).remote is not None


def test_exactly_one_key_source():
    base = {"issuer": ISS, "audience": AUD, "claim_mapping": MAPPING}
    for extra in (
        {},
        {"jwks": JWKS, "jwks_uri": "https://idp.example.com/j"},
        {"jwks_file": "x.json", "jwks_uri": "https://idp.example.com/j"},
        {"jwks": JWKS, "jwks_file": "x.json", "jwks_uri": "https://idp.example.com/j"},
    ):
        with pytest.raises(ConfigError):
            OidcVerifier.from_config(json.dumps(base | extra), frozenset(ROLES))
    assert OidcVerifier.from_config(json.dumps(base | {"jwks": JWKS}), frozenset(ROLES)).remote is None


def test_jwks_settings_from_env():
    d = JwksSettings.from_env({})
    assert (d.ttl, d.min_refresh, d.max_stale) == (300.0, 30.0, 3600.0)
    s = JwksSettings.from_env(
        {"ALES_OIDC_JWKS_TTL": "10", "ALES_OIDC_JWKS_MIN_REFRESH": "0", "ALES_OIDC_JWKS_MAX_STALE": "99"}
    )
    assert (s.ttl, s.min_refresh, s.max_stale) == (10.0, 0.0, 99.0)
    for bad in ({"ALES_OIDC_JWKS_TTL": "0"}, {"ALES_OIDC_JWKS_TTL": "x"}, {"ALES_OIDC_JWKS_MAX_STALE": "-1"}):
        with pytest.raises(ConfigError):
            JwksSettings.from_env(bad)


def test_remote_jwks_direct_clock_and_defaults():
    r = RemoteJwks("http://127.0.0.1:9/jwks.json")  # nothing listens: connection refused is a clean failure
    with pytest.raises(OidcError, match="unavailable"):
        r.keyset("rk1")


def test_jwks_uri_end_to_end_through_the_app(jwks_server):
    env = {"ALES_OIDC_CONFIG": uri_config(jwks_server.url), "ALES_OIDC_JWKS_MIN_REFRESH": "0"}
    app = create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env=env)
    with TestClient(app) as tc:
        assert get(tc, mint()).status_code == 200
        assert jwks_server.count == 1
        jwks_server.serve(rsa_jwk(OTHER_RSA, "rk9"))  # rotation: kid rk1 retired, rk9 introduced
        assert get(tc, mint(kid="rk9", key=OTHER_RSA)).status_code == 200
        assert get(tc, mint()).status_code == 401  # retired key no longer verifies after the refetch


def test_jwks_uri_unreachable_is_401_through_the_app(jwks_server):
    jwks_server.status = 500
    app = create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_OIDC_CONFIG": uri_config(jwks_server.url)})
    with TestClient(app) as tc:
        r = get(tc, mint())
        assert r.status_code == 401
        assert get(tc, "tok-t1-read").status_code == 200  # non-JWT static tokens are unaffected
