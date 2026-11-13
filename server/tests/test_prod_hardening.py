"""P0 production hardening: production mode, credential denylist, token hot reload, audit anchoring."""

from __future__ import annotations

import json
import logging
import os

import pytest
from ales_core import AuditLog, audit_head
from ales_server import create_app
from ales_server.config import ConfigError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from server_helpers import TOKENS, FakeClock, authorize_body, bearer, chain, seed_b64
from sqlalchemy import select
from test_oidc import claims, config, mint

READ = bearer("tok-t1-read")
ALL = bearer("tok-t1-all")
KEY = seed_b64(Ed25519PrivateKey.generate())


# =========================================================================== production mode
def prod_env(**over):
    env = {
        "ALES_ENV": "production",
        "ALES_REQUIRE_SIGNATURES": "1",
        "ALES_SNAPSHOT_KEY": KEY,
        "ALES_ALLOW_SQLITE": "1",
    }
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


def prod_app(tmp_path, env=None, **kw):
    kw.setdefault("tokens", TOKENS)
    return create_app(f"sqlite:///{tmp_path / 'p.db'}", outbox_interval=0, env=prod_env() if env is None else env, **kw)


def test_production_good_config_starts_and_defaults_workloads_to_strict(tmp_path):
    app = prod_app(tmp_path)
    assert app.state.settings.production is True
    assert app.state.settings.enforce_workloads == "strict"
    assert prod_app(tmp_path, prod_env(ALES_ENFORCE_WORKLOADS="auto")).state.settings.enforce_workloads == "auto"


VIOLATIONS = {
    "no_auth": ({"tokens": {}}, {}, "no authentication configured"),
    "anonymous_1": ({}, {"ALES_DEV_ALLOW_ANONYMOUS": "1"}, "ALES_DEV_ALLOW_ANONYMOUS"),
    "anonymous_0": ({}, {"ALES_DEV_ALLOW_ANONYMOUS": "0"}, "ALES_DEV_ALLOW_ANONYMOUS"),
    "signatures_off": ({}, {"ALES_REQUIRE_SIGNATURES": None}, "ALES_REQUIRE_SIGNATURES"),
    "no_key": ({}, {"ALES_SNAPSHOT_KEY": None}, "ALES_SNAPSHOT_KEY"),
    "sqlite": ({}, {"ALES_ALLOW_SQLITE": None}, "SQLite"),
    "workloads_off": ({}, {"ALES_ENFORCE_WORKLOADS": "off"}, "ALES_ENFORCE_WORKLOADS=off"),
}


@pytest.mark.parametrize("name", sorted(VIOLATIONS))
def test_each_production_violation_alone_refuses_start(tmp_path, name):
    kw, over, needle = VIOLATIONS[name]
    with pytest.raises(ConfigError) as exc:
        prod_app(tmp_path, prod_env(**over), **kw)
    msg = str(exc.value)
    assert needle in msg and "1 violation(s)" in msg


def test_all_production_violations_reported_at_once(tmp_path):
    env = {"ALES_ENV": "production", "ALES_DEV_ALLOW_ANONYMOUS": "1", "ALES_ENFORCE_WORKLOADS": "off"}
    with pytest.raises(ConfigError) as exc:
        create_app(f"sqlite:///{tmp_path / 'p.db'}", tokens={}, outbox_interval=0, env=env)
    msg = str(exc.value)
    assert "6 violation(s)" in msg
    for needle in ("no authentication", "ALES_DEV_ALLOW_ANONYMOUS", "ALES_REQUIRE_SIGNATURES", "ALES_SNAPSHOT_KEY",
                   "SQLite", "ALES_ENFORCE_WORKLOADS=off"):
        assert needle in msg


def test_explicit_production_overrides_start_and_log(tmp_path, caplog):
    env = prod_env(
        ALES_REQUIRE_SIGNATURES=None,
        ALES_ALLOW_UNSIGNED_INGRESS="1",
        ALES_SNAPSHOT_KEY=None,
        ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY="1",
    )
    with caplog.at_level(logging.WARNING, logger="ales.server"):
        app = prod_app(tmp_path, env)
    assert app.state.settings.require_signatures is False
    text = caplog.text
    assert "ALES_ALLOW_UNSIGNED_INGRESS=1" in text and "ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY=1" in text
    assert "ALES_ALLOW_SQLITE=1" in text


def test_production_requires_key_even_with_signatures_off_override(tmp_path):
    env = prod_env(ALES_REQUIRE_SIGNATURES=None, ALES_ALLOW_UNSIGNED_INGRESS="1", ALES_SNAPSHOT_KEY=None)
    with pytest.raises(ConfigError, match="ALES_SNAPSHOT_KEY"):
        prod_app(tmp_path, env)


def test_oidc_alone_satisfies_production_auth(tmp_path):
    app = prod_app(tmp_path, prod_env(ALES_OIDC_CONFIG=config()), tokens={})
    assert app.state.auth.oidc is not None


def test_invalid_ales_env_is_a_config_error():
    with pytest.raises(ConfigError, match="ALES_ENV"):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_ENV": "prod"})


def test_development_mode_logs_banner_listing_unsafe_settings(caplog):
    env = {"ALES_DEV_ALLOW_ANONYMOUS": "1"}
    with caplog.at_level(logging.WARNING, logger="ales.server"):
        create_app("sqlite://", tokens={}, outbox_interval=0, env=env)
    banners = [r.getMessage() for r in caplog.records if "ALES DEVELOPMENT MODE" in r.getMessage()]
    assert len(banners) == 1
    for needle in ("anonymous authentication", "ephemeral snapshot key", "signature ingress OFF", "SQLite"):
        assert needle in banners[0]


def test_development_mode_unchanged_behaviour(make_client):
    c = make_client()  # sqlite, tokens, signatures off, ephemeral key: all still start
    assert c.get("/v1/healthz").status_code == 200


# ====================================================================================== denylist
def write(path, obj):
    path.write_text(json.dumps(obj) if not isinstance(obj, str) else obj, encoding="utf-8")


def bump(path, seconds=10):
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + seconds * 1_000_000_000))


def deny_app(path, **kw):
    app = create_app("sqlite://", tokens=kw.pop("tokens", TOKENS), outbox_interval=0,
                     env={"ALES_DENYLIST_FILE": str(path), **kw.pop("env", {})})
    clock = FakeClock()
    app.state.auth.denylist.clock = clock
    return app, clock


def get(tc, headers, path="/v1/outbox/stats"):
    return tc.get(path, headers=headers)


def test_denylisted_static_subject_gets_401_others_fine(tmp_path):
    f = tmp_path / "deny.json"
    write(f, {"subjects": ["reader-t1"]})
    app, _ = deny_app(f)
    with TestClient(app) as tc:
        r = get(tc, READ)
        assert r.status_code == 401 and r.json() == {"detail": "missing or invalid credentials"}
        assert get(tc, ALL).status_code == 200  # unlisted subject unaffected
        assert "ales_denylist_rejections_total 1" in tc.get("/v1/metrics", headers=ALL).text


def test_denylist_change_is_picked_up_after_reload_interval(tmp_path):
    f = tmp_path / "deny.json"
    write(f, {"subjects": []})
    app, clock = deny_app(f)
    with TestClient(app) as tc:
        assert get(tc, READ).status_code == 200
        write(f, {"subjects": ["reader-t1"]})
        bump(f)
        clock.advance(1)  # inside the 5 s poll interval: not yet re-read
        assert get(tc, READ).status_code == 200
        clock.advance(5)
        assert get(tc, READ).status_code == 401
        write(f, {"subjects": []})  # un-deny
        bump(f, 20)
        clock.advance(6)
        assert get(tc, READ).status_code == 200


def test_malformed_denylist_on_reload_keeps_last_good(tmp_path, caplog):
    f = tmp_path / "deny.json"
    write(f, {"subjects": ["reader-t1"]})
    app, clock = deny_app(f)
    with TestClient(app) as tc:
        write(f, "{not json")
        bump(f)
        clock.advance(6)
        with caplog.at_level(logging.ERROR):
            assert get(tc, READ).status_code == 401  # last good list still enforced
        assert "denylist reload failed" in caplog.text
        write(f, {"subjects": "reader-t1"})  # wrong shape: also rejected, last good kept
        bump(f, 20)
        clock.advance(6)
        assert get(tc, READ).status_code == 401
        assert get(tc, ALL).status_code == 200


def test_malformed_or_missing_denylist_at_startup_is_a_config_error(tmp_path):
    f = tmp_path / "deny.json"
    write(f, "{not json")
    with pytest.raises(ConfigError, match="ALES_DENYLIST_FILE"):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_DENYLIST_FILE": str(f)})
    with pytest.raises(ConfigError, match="ALES_DENYLIST_FILE"):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0,
                   env={"ALES_DENYLIST_FILE": str(tmp_path / "absent.json")})


def test_denylisted_oidc_sub_gets_401_and_unlisted_is_fine(tmp_path):
    f = tmp_path / "deny.json"
    write(f, {"jwt_subs": ["alice@idp"]})
    app, _ = deny_app(f, env={"ALES_OIDC_CONFIG": config()})
    with TestClient(app) as tc:
        r = get(tc, bearer(mint()))
        assert r.status_code == 401 and r.json() == {"detail": "missing or invalid credentials"}
        assert get(tc, bearer(mint(claims(sub="bob@idp")))).status_code == 200
        # jwt_subs is OIDC-only: a static token whose subject equals a listed jwt sub is not affected
        assert get(tc, ALL).status_code == 200


def test_subjects_list_also_covers_oidc_and_oidc_never_hits_static_registry(tmp_path):
    f = tmp_path / "deny.json"
    write(f, {"subjects": ["alice@idp"]})
    app, _ = deny_app(f, env={"ALES_OIDC_CONFIG": config()})
    with TestClient(app) as tc:
        assert get(tc, bearer(mint())).status_code == 401


def test_denylist_key_ids_are_not_enforced_but_warn(tmp_path, caplog):
    f = tmp_path / "deny.json"
    write(f, {"key_ids": ["k1"]})
    with caplog.at_level(logging.WARNING):
        app, _ = deny_app(f)
    assert "key_ids are not enforced" in caplog.text
    with TestClient(app) as tc:
        assert get(tc, READ).status_code == 200


# ================================================================================ token hot reload
def tok_file(path, tokens):
    write(path, tokens)


def rec(subject, roles=("read",), tenant="t1"):
    return {"tenant_id": tenant, "roles": list(roles), "subject": subject}


def reload_app(path):
    app = create_app("sqlite://", outbox_interval=0, env={"ALES_TOKENS_FILE": str(path)})
    clock = FakeClock()
    app.state.auth.reloader.watch.set_clock(clock)
    return app, clock


def test_token_file_hot_reload_adds_and_removes_tokens(tmp_path):
    f = tmp_path / "tokens.json"
    tok_file(f, {"tok-a": rec("a")})
    app, clock = reload_app(f)
    with TestClient(app) as tc:
        assert get(tc, bearer("tok-a")).status_code == 200
        assert get(tc, bearer("tok-b")).status_code == 401
        tok_file(f, {"tok-a": rec("a"), "tok-b": rec("b")})
        bump(f)
        clock.advance(1)
        assert get(tc, bearer("tok-b")).status_code == 401  # inside the poll interval
        clock.advance(5)
        assert get(tc, bearer("tok-b")).status_code == 200  # one reload later the new token works
        tok_file(f, {"tok-b": rec("b")})  # rotate: a removed
        bump(f, 20)
        clock.advance(6)
        assert get(tc, bearer("tok-a")).status_code == 401
        assert get(tc, bearer("tok-b")).status_code == 200
        text = tc.get("/v1/metrics", headers=bearer("tok-b")).text
        assert 'ales_token_reloads_total{outcome="ok"} 2' in text


def test_invalid_token_file_reload_keeps_previous_registry(tmp_path, caplog):
    f = tmp_path / "tokens.json"
    tok_file(f, {"tok-a": rec("a")})
    app, clock = reload_app(f)
    with TestClient(app) as tc:
        tok_file(f, {"tok-c": {"tenant_id": "t1", "roles": ["nope"], "subject": "c"}})
        bump(f)
        clock.advance(6)
        with caplog.at_level(logging.ERROR):
            assert get(tc, bearer("tok-a")).status_code == 200
        assert get(tc, bearer("tok-c")).status_code == 401
        assert "token reload failed" in caplog.text
        assert 'ales_token_reloads_total{outcome="error"} 1' in tc.get("/v1/metrics", headers=bearer("tok-a")).text


def test_empty_token_file_reload_revokes_everything(tmp_path):
    f = tmp_path / "tokens.json"
    tok_file(f, {"tok-a": rec("a")})
    app, clock = reload_app(f)
    with TestClient(app) as tc:
        tok_file(f, {})
        bump(f)
        clock.advance(6)
        assert get(tc, bearer("tok-a")).status_code == 401


# ============================================================================== audit anchoring
def _rows(app):
    with app.state.session_factory() as s:
        return list(s.scalars(select(AuditLog).where(AuditLog.tenant_id == "t1").order_by(AuditLog.seq)))


def test_audit_head_endpoint_shape_and_matches_core_head(client):
    r = client.get("/v1/audit/head")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"tenant_id", "seq", "head_hash", "at"}
    assert body["tenant_id"] == "t1" and body["seq"] == 0 and body["head_hash"] == "0" * 64
    src, _, _ = chain()
    client.post("/v1/sources", json=src)
    client.post("/v1/authorize", json=authorize_body("t1", src["context_id"]))
    body = client.get("/v1/audit/head").json()
    with client.app.state.session_factory() as s:
        assert (body["seq"], body["head_hash"]) == audit_head(s, "t1")
    assert body["seq"] >= 1 and body["at"].endswith("Z")
    assert client.get("/v1/audit/head", headers=READ).status_code == 200  # read role is enough
    assert client.get("/v1/audit/head", headers=bearer("tok-t1-ingest")).status_code == 403
    assert client.get("/v1/audit/head", headers=bearer("tok-t2-all")).json()["tenant_id"] == "t2"


def test_audit_verify_does_not_append(client):
    src, _, _ = chain()
    client.post("/v1/sources", json=src)
    client.post("/v1/authorize", json=authorize_body("t1", src["context_id"]))
    before = client.get("/v1/audit/head").json()
    n = len(_rows(client.app))
    for _ in range(3):
        assert client.get("/v1/audit/verify").json()["ok"] is True
    assert len(_rows(client.app)) == n
    after = client.get("/v1/audit/head").json()
    assert (after["seq"], after["head_hash"]) == (before["seq"], before["head_hash"])


def test_audit_export_file_matches_appended_records(tmp_path):
    out = tmp_path / "anchor.jsonl"
    app = create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_AUDIT_EXPORT_FILE": str(out)})
    with TestClient(app, headers=ALL) as tc:
        src, chunk, _ = chain()
        tc.post("/v1/sources", json=src)
        tc.post("/v1/derivations", json=chunk)
        tc.post("/v1/authorize", json=authorize_body("t1", chunk["context_id"]))
        tc.post("/v1/authorize", json=authorize_body("t1", chunk["context_id"]))
    lines = [json.loads(x) for x in out.read_text(encoding="utf-8").splitlines()]
    rows = _rows(app)
    assert len(rows) >= 2 and len(lines) == len(rows)
    for line, row in zip(lines, rows, strict=True):
        assert (line["seq"], line["hash"], line["prev_hash"], line["actor"], line["action"], line["tenant_id"]) == (
            row.seq, row.hash, row.prev_hash, row.actor, row.action, row.tenant_id)
        assert line["detail"] == row.detail
    assert lines[-1]["hash"] == tc_head(app)


def tc_head(app):
    with app.state.session_factory() as s:
        return audit_head(s, "t1")[1]


def test_audit_export_failure_never_fails_the_request_and_is_counted(tmp_path, caplog):
    out = tmp_path / "anchor.jsonl"
    app = create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_AUDIT_EXPORT_FILE": str(out)})
    app.state.audit_exporter.path = str(tmp_path)  # a directory: open(..., "a") fails
    with TestClient(app, headers=ALL) as tc:
        src, _, _ = chain()
        with caplog.at_level(logging.ERROR):
            assert tc.post("/v1/sources", json=src).status_code in (200, 201)
            assert tc.post("/v1/authorize", json=authorize_body("t1", src["context_id"])).status_code == 200
        assert "audit export failed" in caplog.text
        text = tc.get("/v1/metrics").text
        failures = [x for x in text.splitlines() if x.startswith("ales_audit_export_failures_total ")]
        assert failures and int(failures[0].split()[1]) >= 1


def test_audit_export_unusable_path_is_a_startup_error(tmp_path):
    with pytest.raises(ConfigError, match="ALES_AUDIT_EXPORT_FILE"):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0,
                   env={"ALES_AUDIT_EXPORT_FILE": str(tmp_path / "no" / "such" / "dir" / "a.jsonl")})


# ================================================================================ /v1/verify role
def test_verify_requires_ingest_role(client):
    body = {"tenant_id": "t1"}
    assert client.post("/v1/verify", json=body, headers=READ).status_code == 403
    assert client.post("/v1/verify", json=body, headers=bearer("tok-t1-revoke")).status_code == 403
    r = client.post("/v1/verify", json=body, headers=bearer("tok-t1-ingest"))
    assert r.status_code == 200 and r.json()["passed"] is True
