"""ALES_REQUIRE_GRANTS: pins the grants gate; default off in development, on in production."""

from __future__ import annotations

import logging

from ales_server import create_app
from fastapi.testclient import TestClient
from server_helpers import TOKENS, authorize_body, chain

ADMIN = {"Authorization": "Bearer tok-t1-admin"}


def _setup(client) -> tuple[dict, str]:
    src, chunk, summ = chain()
    for env, path in ((src, "sources"), (chunk, "derivations"), (summ, "derivations")):
        assert client.post(f"/v1/{path}", json=env).status_code == 200
    r = client.post(
        "/v1/workloads", json={"workload_id": "ag1", "kind": "agent", "display_name": "Agent 1"}, headers=ADMIN
    )
    assert r.status_code in (200, 201), r.text
    return authorize_body("t1", summ["context_id"]) | {"agent_id": "ag1"}, summ["context_id"]


def test_default_off_agent_allowed_without_any_grant(make_client):
    c = make_client(enforce_workloads="strict")
    assert c.app.state.settings.require_grants is False
    body, _ = _setup(c)
    assert c.post("/v1/authorize", json=body).json()["decision"] == "ALLOW"  # tenant has zero grants: gate not pinned


def test_on_denies_principal_without_grant_even_with_zero_grant_rows(make_client):
    c = make_client(enforce_workloads="strict", env={"ALES_REQUIRE_GRANTS": "1"})
    assert c.app.state.settings.require_grants is True
    body, _ = _setup(c)
    out = c.post("/v1/authorize", json=body).json()
    assert out["decision"] == "DENY" and out["reason"] == ["PRINCIPAL_NOT_IN_SCOPE"]
    assert c.post("/v1/workloads/ag1/grants", json={"principal_id": "alice"}, headers=ADMIN).status_code in (200, 201)
    assert c.post("/v1/authorize", json=body).json()["decision"] == "ALLOW"
    c.delete("/v1/workloads/ag1/grants/alice", headers=ADMIN)  # deleting the last grant does not reopen the gate
    assert c.post("/v1/authorize", json=body).json()["decision"] == "DENY"
    # requests without an agent_id are not affected
    assert c.post("/v1/authorize", json=authorize_body("t1", body["objects"][0]["context_id"])).json()["decision"] == "ALLOW"


def test_explicit_argument_overrides_env(make_client):
    c = make_client(enforce_workloads="strict", require_grants=True, env={"ALES_REQUIRE_GRANTS": "0"})
    assert c.app.state.settings.require_grants is True


def test_production_defaults_on_and_can_be_switched_off_explicitly():
    prod = {
        "ALES_ENV": "production",
        "ALES_SNAPSHOT_KEY": "",
        "ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY": "1",
        "ALES_ALLOW_SQLITE": "1",
        "ALES_REQUIRE_SIGNATURES": "1",
    }
    app = create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env=prod)
    assert app.state.settings.require_grants is True
    off = create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={**prod, "ALES_REQUIRE_GRANTS": "0"})
    assert off.state.settings.require_grants is False


def test_malformed_value_is_a_startup_error():
    import pytest
    from ales_server.config import ConfigError

    with pytest.raises(ConfigError):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_REQUIRE_GRANTS": "maybe"})


def test_production_without_purge_targets_logs_error_once(caplog):
    prod = {
        "ALES_ENV": "production",
        "ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY": "1",
        "ALES_ALLOW_SQLITE": "1",
        "ALES_REQUIRE_SIGNATURES": "1",
    }
    with caplog.at_level(logging.ERROR, logger="ales.server"):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env=prod)
    msgs = [r for r in caplog.records if "LOG-ONLY" in r.getMessage()]
    assert len(msgs) == 1 and msgs[0].levelno == logging.ERROR
    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="ales.server"):
        TestClient(create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={}))  # development: no error
    assert not [r for r in caplog.records if "LOG-ONLY" in r.getMessage()]
