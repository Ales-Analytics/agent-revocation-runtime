"""Per-token JWT revocation: ``jwt_jtis`` in the denylist file and ``require_jti`` in the OIDC config."""

from __future__ import annotations

import json
import os

import pytest
from ales_server import create_app
from ales_server.config import ConfigError
from ales_server.oidc import OidcError, OidcVerifier
from fastapi.testclient import TestClient
from server_helpers import TOKENS, FakeClock, bearer
from test_oidc import ROLES, claims, config, mint

PATH = "/v1/outbox/stats"


def _write(path, obj):
    path.write_text(json.dumps(obj), encoding="utf-8")


def _bump(path, seconds=10):
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + seconds * 1_000_000_000))


def _app(f, **cfg_over):
    app = create_app(
        "sqlite://",
        tokens=TOKENS,
        outbox_interval=0,
        env={"ALES_DENYLIST_FILE": str(f), "ALES_OIDC_CONFIG": config(**cfg_over)},
    )
    clock = FakeClock()
    app.state.auth.denylist.clock = clock
    return app, clock


def _get(tc, tok):
    return tc.get(PATH, headers=bearer(tok))


def test_listed_jti_rejected_unlisted_fine(tmp_path):
    f = tmp_path / "d.json"
    _write(f, {"jwt_jtis": ["bad-1"]})
    app, _ = _app(f)
    with TestClient(app) as tc:
        r = _get(tc, mint(claims(jti="bad-1")))
        assert r.status_code == 401 and r.json() == {"detail": "missing or invalid credentials"}
        assert _get(tc, mint(claims(jti="good-1"))).status_code == 200
        # the same subject with another jti is untouched: revocation is per token
        assert _get(tc, mint(claims(jti="good-2", sub="alice@idp"))).status_code == 200
        metrics = tc.get("/v1/metrics", headers=bearer("tok-t1-all")).text
        assert "ales_denylist_rejections_total 1" in metrics


def test_missing_jti_allowed_even_with_nonempty_list_by_default(tmp_path):
    f = tmp_path / "d.json"
    _write(f, {"jwt_jtis": ["bad-1"]})
    app, _ = _app(f)
    with TestClient(app) as tc:
        assert _get(tc, mint(claims())).status_code == 200


def test_require_jti_rejects_tokens_without_jti(tmp_path):
    f = tmp_path / "d.json"
    _write(f, {"jwt_jtis": []})
    app, _ = _app(f, require_jti=True)
    with TestClient(app) as tc:
        assert _get(tc, mint(claims())).status_code == 401
        assert _get(tc, mint(claims(jti="x"))).status_code == 200


def test_require_jti_must_be_boolean():
    with pytest.raises(ConfigError, match="require_jti"):
        OidcVerifier.from_config(config(require_jti="yes"), ROLES)


def test_non_string_or_empty_jti_is_rejected():
    v = OidcVerifier.from_config(config(), ROLES)
    for bad in (123, "", ["a"]):
        with pytest.raises(OidcError):
            v.verify_claims(mint(claims(jti=bad)))
    assert v.verify_claims(mint(claims(jti="ok")))[3] == "ok"
    assert v.verify_claims(mint(claims()))[3] is None


def test_hot_reload_picks_up_new_jti_within_the_interval(tmp_path):
    f = tmp_path / "d.json"
    _write(f, {"jwt_jtis": []})
    app, clock = _app(f)
    tok = mint(claims(jti="t-9"))
    with TestClient(app) as tc:
        assert _get(tc, tok).status_code == 200
        _write(f, {"jwt_jtis": ["t-9"]})
        _bump(f)
        clock.advance(1)  # inside the 5 s poll interval: not yet re-read
        assert _get(tc, tok).status_code == 200
        clock.advance(5)
        assert _get(tc, tok).status_code == 401
        _write(f, {"jwt_jtis": []})  # un-revoke
        _bump(f, 20)
        clock.advance(6)
        assert _get(tc, tok).status_code == 200


def test_jwt_jtis_shape_is_validated(tmp_path):
    f = tmp_path / "d.json"
    _write(f, {"jwt_jtis": "bad-1"})
    with pytest.raises(ConfigError, match="jwt_jtis"):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env={"ALES_DENYLIST_FILE": str(f)})
