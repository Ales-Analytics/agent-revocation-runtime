"""Authentication, tenant binding and role enforcement: the trust boundary, negative-test heavy."""

from __future__ import annotations

import hmac
import json
import logging
import uuid

import pytest
from ales_server import create_app
from ales_server.auth import ROLES, Authenticator, TokenRegistry, bind_tenant, parse_bearer
from ales_server.config import ConfigError
from fastapi.testclient import TestClient
from server_helpers import ALL, T2, TOKENS, P, authorize_body, bearer, chain

MISMATCH = {"detail": "tenant mismatch with credential"}
EXEMPT = {"/v1/healthz", "/v1/readyz"}
UID = str(uuid.uuid4())


def _anon(app_client: TestClient) -> TestClient:
    """Same app, no default credentials."""
    return TestClient(app_client.app)


def _concrete(path: str) -> str:
    return (
        path.replace("{context_id}", UID)
        .replace("{key_id}", "k1")
        .replace("{policy_id}", "p1")
        .replace("{version}", "1")
        .replace("{workload_id}", "w1")
        .replace("{delegation_id}", "d1")
        .replace("{approval_id}", "a1")
        .replace("{row_id}", "5")
    )


def _all_routes(app):
    """Every (METHOD, path) the app serves under /v1, taken from its generated OpenAPI document."""
    out = []
    for path, ops in app.openapi()["paths"].items():
        if path.startswith("/v1"):
            for m in ops:
                out.append((m.upper(), path))
    return sorted(out)


# --------------------------------------------------------------------------- 401: every route class
def test_every_protected_route_requires_credentials(client):
    """Enumerates the live route table, so a route added later without auth fails this test."""
    anon = _anon(client)
    routes = _all_routes(client.app)
    assert len(routes) >= 29
    for method, path in routes:
        r = anon.request(method, _concrete(path), json={} if method in ("POST", "PATCH") else None)
        if path in EXEMPT:
            assert r.status_code in (200, 503), (method, path)
        else:
            assert r.status_code == 401, (method, path, r.status_code)
            assert r.headers["www-authenticate"] == "Bearer"
            assert r.json() == {"detail": "missing or invalid credentials"}


@pytest.mark.parametrize(
    "header",
    [
        "Bearer wrong-token",
        "Bearer tok-t1-al",  # prefix of a valid token
        "Bearer tok-t1-all-extra",  # valid token plus suffix
        "Bearer TOK-T1-ALL",  # case differs
        "Bearer  tok-t1-all",  # double space
        "Bearer tok-t1-all ",  # trailing space
        "Bearer",
        "Bearer ",
        "Basic tok-t1-all",
        "tok-t1-all",
        "Token tok-t1-all",
        "",
    ],
)
def test_bad_authorization_headers_rejected(client, header):
    anon = _anon(client)
    for method, path, body in [
        ("POST", "/v1/sources", chain()[0]),
        ("POST", "/v1/revocations", {"source_id": UID, "reason": "deleted"}),
        ("POST", "/v1/authorize", authorize_body("t1", UID)),
        ("GET", "/v1/snapshot", None),
        ("GET", "/v1/admin/keys", None),
        ("GET", "/v1/audit/verify", None),
    ]:
        r = anon.request(method, path, json=body, headers={"Authorization": header})
        assert r.status_code == 401, (path, header)


def test_lowercase_scheme_accepted(client):
    r = _anon(client).get("/v1/snapshot", headers={"Authorization": "bearer tok-t1-all"})
    assert r.status_code == 200


def test_tenant_header_does_not_authenticate(client):
    r = _anon(client).get("/v1/snapshot", headers={"X-Tenant-Id": "t1"})
    assert r.status_code == 401


def test_health_and_ready_are_public(client):
    anon = _anon(client)
    assert anon.get("/v1/healthz").status_code == 200
    assert anon.get("/v1/readyz").status_code == 200
    # public even with a garbage credential: they never consult it
    assert anon.get("/v1/healthz", headers={"Authorization": "Bearer nope"}).status_code == 200


def test_unknown_path_requires_auth_too(client):
    anon = _anon(client)
    assert anon.get("/v1/does-not-exist").status_code == 401
    assert anon.get("/openapi.json").status_code == 401
    assert anon.get("/docs").status_code == 401


# ------------------------------------------------------------------------------- 403: tenant spoof
def test_body_tenant_spoof_403_everywhere(client):
    other_src, other_chunk, _ = chain("t2")
    expect = MISMATCH
    assert client.post("/v1/sources", json=other_src).json() == expect
    assert client.post("/v1/sources", json=other_src).status_code == 403
    assert client.post("/v1/derivations", json=other_chunk).status_code == 403
    rev = {"tenant_id": "t2", "source_id": other_src["context_id"], "reason": "deleted"}
    r = client.post("/v1/revocations", json=rev)
    assert r.status_code == 403 and r.json() == expect
    r = client.post("/v1/authorize", json=authorize_body("t2", UID))
    assert r.status_code == 403 and r.json() == expect
    r = client.post("/v1/verify", json={"tenant_id": "t2"})
    assert r.status_code == 403 and r.json() == expect
    r = client.post("/v1/admin/keys", json={"key_id": "k", "tenant_id": "t2", "public_key_b64": "A" * 43 + "="})
    assert r.status_code == 403 and r.json() == expect
    # nothing was created under either tenant
    assert client.get(f"/v1/lineage/{other_src['context_id']}", headers=T2).status_code == 404
    assert client.get("/v1/admin/keys", headers=T2).json() == {"keys": []}


def test_header_tenant_spoof_403_on_every_authenticated_route(client):
    spoof = {"X-Tenant-Id": "t2"}
    for method, path in _all_routes(client.app):
        if path in EXEMPT:
            continue
        r = client.request(method, _concrete(path), json={} if method in ("POST", "PATCH") else None, headers=spoof)
        assert r.status_code == 403 and r.json() == MISMATCH, (method, path, r.status_code)


def test_matching_tenant_header_is_fine(client):
    assert client.get("/v1/snapshot", headers={"X-Tenant-Id": "t1"}).status_code == 200


def test_query_tenant_spoof_403(client):
    assert client.get(f"/v1/lineage/{UID}", params={"tenant_id": "t2"}).status_code == 403
    assert client.get("/v1/snapshot", params={"tenant_id": "t2"}).json() == MISMATCH
    # repeated parameter: every value must match
    r = client.get(f"/v1/lineage/{UID}", params=[("tenant_id", "t1"), ("tenant_id", "t2")])
    assert r.status_code == 403
    r = client.get(f"/v1/lineage/{UID}", params=[("tenant_id", "t2"), ("tenant_id", "t1")])
    assert r.status_code == 403


def test_duplicate_tenant_headers_spoof_403(client):
    r = client.get("/v1/snapshot", headers=[("X-Tenant-Id", "t1"), ("X-Tenant-Id", "t2")])
    assert r.status_code == 403


def test_non_string_body_tenant_is_a_mismatch(client):
    for bad in (123, ["t1"], {"id": "t1"}, "", "T1", "t1 "):
        r = client.post("/v1/revocations", json={"tenant_id": bad, "source_id": UID, "reason": "deleted"})
        assert r.status_code == 403, bad


def test_tenant_comes_from_token_when_body_omits_it(client):
    src, chunk, _ = chain("t1")
    assert client.post("/v1/sources", json=src).status_code == 200
    r = client.post("/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"})
    assert r.status_code == 200
    # the event landed in the token's tenant, i.e. it really revoked t1's source
    r = client.post("/v1/derivations", json=chunk)
    assert r.status_code == 200
    body = client.post("/v1/authorize", json=authorize_body("t1", chunk["context_id"])).json()
    assert body["decision"] == "DENY"


def test_tenants_are_isolated(client):
    src, chunk, summ = chain("t1")
    for env, path in ((src, "/v1/sources"), (chunk, "/v1/derivations"), (summ, "/v1/derivations")):
        assert client.post(path, json=env).status_code == 200
    # t2 revoking t1's source id is a durable no-op for t1 (its own tenant has no such source)
    r = client.post(
        "/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"}, headers=T2
    )
    assert r.status_code == 200
    body = client.post("/v1/authorize", json=authorize_body("t1", summ["context_id"])).json()
    assert body["decision"] == "ALLOW"
    assert client.get(f"/v1/lineage/{summ['context_id']}", headers=T2).status_code == 404
    assert client.get("/v1/outbox/stats", headers=T2).json()["totals"]["pending"] == 0


# ----------------------------------------------------------------------------------- 403: roles
# (method, path, json body, required role). Bodies are deliberately invalid/minimal: an allowed
# role must get past authorization (any status other than 401/403), a disallowed role must get 403.
ROLE_TABLE = [
    ("POST", "/v1/sources", {}, "ingest"),
    ("POST", "/v1/derivations", {}, "ingest"),
    ("POST", "/v1/revocations", {}, "revoke"),
    ("POST", "/v1/authorize", {}, "read"),
    ("GET", f"/v1/lineage/{UID}", None, "read"),
    ("POST", "/v1/verify", {}, "ingest"),
    ("GET", "/v1/audit/head", None, "read"),
    ("GET", "/v1/snapshot", None, "read"),
    ("GET", "/v1/snapshot/public_key", None, "read"),
    ("GET", "/v1/outbox/stats", None, "read"),
    ("GET", "/v1/outbox/dead", None, "admin"),
    ("POST", "/v1/outbox/dead/5/requeue", None, "admin"),
    ("POST", "/v1/outbox/run", None, "admin"),
    ("POST", "/v1/admin/keys", {}, "admin"),
    ("PATCH", "/v1/admin/keys/k1", {}, "admin"),
    ("GET", "/v1/admin/keys", None, "admin"),
    ("GET", "/v1/audit/verify", None, "admin"),
    # v0.3 governance surface
    ("POST", "/v1/policies", {}, "admin"),
    ("GET", "/v1/policies", None, "admin"),
    ("GET", "/v1/policies/p1/versions/1", None, "admin"),
    ("POST", "/v1/policies/p1/versions/1/activate", None, "admin"),
    ("POST", "/v1/workloads", {}, "admin"),
    ("GET", "/v1/workloads", None, "read"),
    ("PATCH", "/v1/workloads/w1", {}, "admin"),
    ("POST", "/v1/workloads/w1/grants", {}, "admin"),
    ("DELETE", "/v1/workloads/w1/grants/pr1", None, "admin"),
    ("GET", "/v1/grants", None, "read"),
    ("POST", "/v1/delegations", {}, "admin"),
    ("GET", "/v1/delegations", None, "read"),
    ("DELETE", "/v1/delegations/d1", None, "admin"),
    ("POST", "/v1/handoffs", {}, "read"),
    ("GET", "/v1/approvals", None, "admin"),
    ("GET", "/v1/approvals/a1", None, "read"),
    ("POST", "/v1/approvals/a1/decide", {}, "admin"),
    ("GET", "/v1/metrics", None, "read"),
]
_TEMPLATES = [
    (UID, "{context_id}"),
    ("/k1", "/{key_id}"),
    ("/policies/p1/versions/1", "/policies/{policy_id}/versions/{version}"),
    ("/workloads/w1", "/workloads/{workload_id}"),
    ("/grants/pr1", "/grants/{principal_id}"),
    ("/delegations/d1", "/delegations/{delegation_id}"),
    ("/approvals/a1", "/approvals/{approval_id}"),
    ("/outbox/dead/5/requeue", "/outbox/dead/{row_id}/requeue"),
]


def _template(path: str) -> str:
    for concrete, tmpl in _TEMPLATES:
        path = path.replace(concrete, tmpl)
    return path
ROLE_TOKENS = {
    "ingest": "tok-t1-ingest",
    "revoke": "tok-t1-revoke",
    "read": "tok-t1-read",
    "admin": "tok-t1-admin",
}


def test_role_table_covers_every_protected_route(client):
    live = {(m, p) for m, p in _all_routes(client.app) if p not in EXEMPT}
    covered = {(m, _template(p)) for m, p, _, _ in ROLE_TABLE}
    assert live == covered


@pytest.mark.parametrize("held", sorted(ROLES))
def test_role_matrix(client, held):
    anon = _anon(client)
    for method, path, body, needed in ROLE_TABLE:
        r = anon.request(method, path, json=body, headers=bearer(ROLE_TOKENS[held]))
        if needed == held:
            assert r.status_code not in (401, 403), (held, method, path, r.status_code)
        else:
            assert r.status_code == 403, (held, method, path, r.status_code)
            assert r.json() == {"detail": f"role '{needed}' required"}


def test_role_checked_before_body_validation_and_side_effects(client):
    src = chain()[0]
    r = _anon(client).post("/v1/sources", json=src, headers=bearer("tok-t1-read"))
    assert r.status_code == 403
    assert client.get(f"/v1/lineage/{src['context_id']}").status_code == 404  # never registered
    # read-only token cannot revoke either
    ok = client.post("/v1/sources", json=src)
    assert ok.status_code == 200
    r = _anon(client).post(
        "/v1/revocations", json={"source_id": src["context_id"], "reason": "deleted"}, headers=bearer("tok-t1-read")
    )
    assert r.status_code == 403


def test_ingest_cannot_revoke_and_revoke_cannot_ingest(client):
    anon = _anon(client)
    src = chain()[0]
    assert anon.post("/v1/sources", json=src, headers=bearer("tok-t1-ingest")).status_code == 200
    rev = {"source_id": src["context_id"], "reason": "deleted"}
    assert anon.post("/v1/revocations", json=rev, headers=bearer("tok-t1-ingest")).status_code == 403
    assert anon.post("/v1/sources", json=chain()[0], headers=bearer("tok-t1-revoke")).status_code == 403
    assert anon.post("/v1/revocations", json=rev, headers=bearer("tok-t1-revoke")).status_code == 200


def test_admin_role_does_not_grant_data_plane(client):
    anon = _anon(client)
    assert anon.post("/v1/sources", json=chain()[0], headers=bearer("tok-t1-admin")).status_code == 403
    assert anon.get("/v1/snapshot", headers=bearer("tok-t1-admin")).status_code == 403


# ------------------------------------------------------------------------- registry / config units
def _rec(**kw):
    base = {"tenant_id": "t", "roles": ["read"], "subject": "s"}
    base.update(kw)
    return base


@pytest.mark.parametrize(
    "records",
    [
        {"tok": _rec(tenant_id="")},
        {"tok": _rec(tenant_id=None)},
        {"tok": _rec(tenant_id=5)},
        {"tok": _rec(tenant_id="a:verify")},
        {"tok": _rec(roles=[])},
        {"tok": _rec(roles="read")},
        {"tok": _rec(roles=["superuser"])},
        {"tok": _rec(roles=["read", 1])},
        {"tok": _rec(subject="")},
        {"tok": {"tenant_id": "t", "roles": ["read"]}},
        {"tok": "not-an-object"},
        {"": _rec()},
        {" tok": _rec()},
        {"to k": _rec()},
        {"to\nk": _rec()},
    ],
)
def test_invalid_token_records_are_startup_errors(records):
    with pytest.raises(ConfigError):
        TokenRegistry(records)
    with pytest.raises(ConfigError):
        create_app("sqlite://", tokens=records)


def test_registry_stores_only_digests():
    reg = TokenRegistry({"super-secret-token-123": _rec()})
    dump = repr(vars(reg)) + repr(reg._entries)
    assert "super-secret-token-123" not in dump
    assert reg.lookup("super-secret-token-123").subject == "s"
    assert reg.lookup("super-secret-token-124") is None
    assert reg.lookup("") is None


def test_lookup_compares_against_every_digest_with_compare_digest(monkeypatch):
    reg = TokenRegistry({f"token-{i}": _rec(subject=f"s{i}") for i in range(5)})
    calls = []
    real = hmac.compare_digest

    def spy(a, b):
        calls.append(1)
        return real(a, b)

    monkeypatch.setattr("ales_server.auth.hmac.compare_digest", spy)
    assert reg.lookup("token-0").subject == "s0"  # first entry: still no early exit
    assert len(calls) == 5
    calls.clear()
    assert reg.lookup("nope") is None
    assert len(calls) == 5


def test_duplicate_token_in_env_and_file_rejected(tmp_path):
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"dup": _rec()}))
    env = {"ALES_TOKENS": json.dumps({"dup": _rec()}), "ALES_TOKENS_FILE": str(f)}
    with pytest.raises(ConfigError, match="both"):
        TokenRegistry.from_sources(env)


def test_tokens_from_env_and_file_are_merged(tmp_path):
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"file-token": _rec(tenant_id="tf")}))
    env = {"ALES_TOKENS": json.dumps({"env-token": _rec(tenant_id="te")}), "ALES_TOKENS_FILE": str(f)}
    reg = TokenRegistry.from_sources(env)
    assert reg.lookup("file-token").tenant_id == "tf" and reg.lookup("env-token").tenant_id == "te"


@pytest.mark.parametrize("raw", ["{not json", "[]", '"str"', "42"])
def test_malformed_env_tokens_fail_closed(raw):
    with pytest.raises(ConfigError):
        TokenRegistry.from_sources({"ALES_TOKENS": raw})
    with pytest.raises(ConfigError):
        create_app("sqlite://", env={"ALES_TOKENS": raw})


def test_unreadable_token_file_fails_closed(tmp_path):
    with pytest.raises(ConfigError):
        TokenRegistry.from_sources({"ALES_TOKENS_FILE": str(tmp_path / "missing.json")})


def test_app_serves_with_tokens_from_env():
    env = {"ALES_TOKENS": json.dumps({"env-tok": _rec(tenant_id="te", roles=ALL)})}
    with TestClient(create_app("sqlite://", env=env, outbox_interval=0)) as c:
        assert c.get("/v1/snapshot").status_code == 401
        r = c.get("/v1/snapshot", headers=bearer("env-tok"))
        assert r.status_code == 200 and r.json()["tenant_id"] == "te"


def test_app_serves_with_tokens_from_file(tmp_path):
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"file-tok": _rec(tenant_id="tf", roles=ALL)}))
    with TestClient(create_app("sqlite://", env={"ALES_TOKENS_FILE": str(f)}, outbox_interval=0)) as c:
        assert c.get("/v1/snapshot", headers=bearer("file-tok")).json()["tenant_id"] == "tf"


def test_parse_bearer_strictness():
    assert parse_bearer("Bearer abc") == "abc"
    assert parse_bearer("BEARER abc") == "abc"
    for bad in (None, "", "Bearer", "Bearer  abc", "Bearer a b", "Basic abc", "Bearer a\tb", "abc"):
        assert parse_bearer(bad) is None


def test_bind_tenant_unit():
    from ales_server.auth import Identity

    ident = Identity("s", "t1", frozenset(ALL))
    assert bind_tenant(ident) == "t1" and bind_tenant(ident, None) == "t1" and bind_tenant(ident, "t1") == "t1"
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as ei:
        bind_tenant(ident, "t2")
    assert ei.value.status_code == 403 and ei.value.detail == "tenant mismatch with credential"


# ------------------------------------------------------------------------------ anonymous dev mode
def test_no_tokens_and_no_flag_refuses_protected_routes(caplog):
    with caplog.at_level(logging.ERROR, logger="ales.server.auth"):
        app = create_app("sqlite://", env={}, outbox_interval=0)
    assert any("no tokens configured" in r.getMessage() for r in caplog.records)
    with TestClient(app) as c:
        assert c.get("/v1/healthz").status_code == 200
        assert c.get("/v1/readyz").status_code == 200
        for method, path in _all_routes(app):
            if path in EXEMPT:
                continue
            r = c.request(method, _concrete(path), json={} if method in ("POST", "PATCH") else None,
                          headers={"X-Tenant-Id": "t1", "Authorization": "Bearer anything"})
            assert r.status_code == 503, (method, path)


def test_anonymous_dev_mode(caplog):
    with caplog.at_level(logging.WARNING, logger="ales.server.auth"):
        app = create_app("sqlite://", env={"ALES_DEV_ALLOW_ANONYMOUS": "1"}, outbox_interval=0)
    warnings = [r.getMessage() for r in caplog.records if "ANONYMOUS" in r.getMessage()]
    assert len(warnings) == 1 and "NEVER USE THIS IN PRODUCTION" in warnings[0]
    with TestClient(app) as c:
        h = {"X-Tenant-Id": "t1"}
        src = chain("t1")[0]
        assert c.post("/v1/sources", json=src, headers=h).status_code == 200
        r = c.post("/v1/authorize", json=authorize_body("t1", src["context_id"]), headers=h)
        assert r.json()["decision"] == "ALLOW"
        # tenant still bound (to the header): a body tenant that disagrees is rejected
        assert c.post("/v1/authorize", json=authorize_body("t2", src["context_id"]), headers=h).status_code == 403
        # no tenant anywhere -> cannot bind one
        assert c.get("/v1/snapshot").status_code == 422
        # a header tenant in the reserved scratch namespace is refused
        assert c.get("/v1/snapshot", headers={"X-Tenant-Id": "t1:verify"}).status_code == 403
        # the audit ledger records the anonymous actor
        assert c.get("/v1/audit/verify", headers=h).json()["ok"] is True


def test_anonymous_flag_ignored_when_tokens_configured(caplog):
    with caplog.at_level(logging.WARNING, logger="ales.server.auth"):
        app = create_app("sqlite://", tokens=TOKENS, allow_anonymous=True, outbox_interval=0)
    assert any("ignored" in r.getMessage() for r in caplog.records)
    with TestClient(app) as c:
        assert c.get("/v1/snapshot", headers={"X-Tenant-Id": "t1"}).status_code == 401


def test_dev_flag_must_be_a_valid_boolean():
    with pytest.raises(ConfigError):
        create_app("sqlite://", env={"ALES_DEV_ALLOW_ANONYMOUS": "maybe"}, outbox_interval=0)


def test_authenticator_without_registry_or_flag_is_not_anonymous():
    a = Authenticator(None, allow_anonymous=False)
    assert a.allow_anonymous is False
    assert Authenticator(TokenRegistry({"t": _rec()}), allow_anonymous=True).allow_anonymous is False


# --------------------------------------------------------------------------- scratch namespace
def test_verify_endpoint_uses_isolated_scratch_namespace(client):
    r = client.post("/v1/verify", json={"tenant_id": "t1"})
    assert r.status_code == 200 and r.json()["passed"] is True
    # nothing leaks into the tenant's own space
    assert client.get("/v1/outbox/stats").json()["totals"]["pending"] == 0
    assert client.get("/v1/snapshot").json()["revocation_epoch"] == 0


def test_valid_token_happy_paths(client):
    src, chunk, summ = chain()
    for env, path in ((src, "/v1/sources"), (chunk, "/v1/derivations"), (summ, "/v1/derivations")):
        r = client.post(path, json=env)
        assert r.status_code == 200 and r.json()["tenant_id"] == "t1"
    r = client.post("/v1/authorize", json={**authorize_body("t1", summ["context_id"]), "principal": P})
    assert r.status_code == 200 and r.json()["decision"] == "ALLOW"
    assert client.get(f"/v1/lineage/{summ['context_id']}").status_code == 200
    assert client.get("/v1/snapshot").status_code == 200
    assert client.get("/v1/outbox/stats").status_code == 200
