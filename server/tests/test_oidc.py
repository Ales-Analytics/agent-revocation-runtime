"""OIDC/JWT bearer authentication: RS256 + ES256, strict claim handling, no registry fall-through."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest
from ales_server import create_app
from ales_server.config import ConfigError
from ales_server.oidc import OidcVerifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient
from server_helpers import TOKENS, bearer

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
