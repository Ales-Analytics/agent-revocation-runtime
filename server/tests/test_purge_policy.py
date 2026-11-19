"""ALES_PURGE_POLICY: production refuses silent log-only purge; deny-only is an explicit, loudly logged choice."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest
from ales_server import create_app
from ales_server.config import ConfigError
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "adapters"))
from server_helpers import T1, TOKENS
from test_prod_hardening import prod_env

TARGETS = json.dumps([{"kind": "cache", "type": "redis", "url": "redis://127.0.0.1:1/0"}])


def _app(tmp_path, env):
    return create_app(f"sqlite:///{tmp_path / 'p.db'}", tokens=TOKENS, outbox_interval=0, env=env)


def test_production_policy_purge_without_targets_refuses_start(tmp_path):
    with pytest.raises(ConfigError, match="ALES_PURGE_TARGETS is not set") as exc:
        _app(tmp_path, prod_env(ALES_PURGE_POLICY="purge"))
    assert "1 violation(s)" in str(exc.value)


def test_production_default_policy_is_purge_and_needs_targets(tmp_path):
    with pytest.raises(ConfigError, match="ALES_PURGE_TARGETS"):
        _app(tmp_path, prod_env(ALES_PURGE_POLICY=None))


def test_production_deny_only_starts_with_one_prominent_warning(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="ales.server"):
        app = _app(tmp_path, prod_env(ALES_PURGE_POLICY="deny-only"))
    msgs = [r for r in caplog.records if "use-time denial only" in r.getMessage()]
    assert len(msgs) == 1 and msgs[0].levelno == logging.WARNING
    assert "revoked bytes remain in stores until purged externally" in msgs[0].getMessage()
    assert app.state.settings.purge_policy == "deny-only"


def test_production_with_targets_is_ok_and_reports_purge_mode(tmp_path):
    app = _app(tmp_path, prod_env(ALES_PURGE_POLICY="purge", ALES_PURGE_TARGETS=TARGETS))
    with TestClient(app) as tc:
        assert tc.get("/v1/outbox/stats", headers=T1).json()["worker"]["handlers"] == "purge:redis"


def test_stats_reports_deny_only_mode(tmp_path):
    app = _app(tmp_path, prod_env(ALES_PURGE_POLICY="deny-only"))
    with TestClient(app) as tc:
        assert tc.get("/v1/outbox/stats", headers=T1).json()["worker"]["handlers"] == "deny_only"


def test_deny_only_contradicting_targets_is_refused_in_any_environment(tmp_path):
    with pytest.raises(ConfigError, match="contradicts"):
        _app(tmp_path, prod_env(ALES_PURGE_POLICY="deny-only", ALES_PURGE_TARGETS=TARGETS))
    with pytest.raises(ConfigError, match="contradicts"):
        create_app(
            "sqlite://",
            tokens=TOKENS,
            outbox_interval=0,
            env={"ALES_PURGE_POLICY": "deny-only", "ALES_PURGE_TARGETS": TARGETS},
        )


def test_invalid_policy_value_is_a_config_error():
    with pytest.raises(ConfigError, match="ALES_PURGE_POLICY"):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_PURGE_POLICY": "maybe"})


def test_development_without_targets_is_unchanged_log_only(caplog):
    with caplog.at_level(logging.WARNING, logger="ales.server"):
        app = create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={})
    with TestClient(app) as tc:
        assert tc.get("/v1/outbox/stats", headers=T1).json()["worker"]["handlers"] == "log_only"


def test_programmatic_outbox_handlers_satisfy_production_purge_rule(tmp_path):
    app = create_app(
        f"sqlite:///{tmp_path / 'p.db'}",
        tokens=TOKENS,
        outbox_interval=0,
        env=prod_env(ALES_PURGE_POLICY="purge"),
        outbox_handlers={"*": lambda r: None},
    )
    assert app.state.settings.purge_policy == "purge"
