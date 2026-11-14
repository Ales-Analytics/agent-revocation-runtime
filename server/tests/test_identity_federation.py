"""Entitlement providers, issuer-qualified principals and group-change invalidation (v0.5)."""

from __future__ import annotations

import json
import time

import pytest
from ales_core import AuditLog
from ales_sdk import InvariantClient, new_source
from ales_server import create_app
from ales_server.config import ConfigError
from ales_server.identity import (
    CallerGroupsRejected,
    EntitlementError,
    EntitlementOutcome,
    EntitlementResolver,
    Entitlements,
    StaticEntitlements,
    resolve_for_request,
)
from fastapi.testclient import TestClient
from server_helpers import T1, TOKENS, TestClientTransport, bearer
from sqlalchemy import select
from test_oidc import AUD, ISS, claims, config, mint

PRINCIPAL = {"type": "user", "id": "alice"}


def _app(doc=None, *, extra_env=None, **kw):
    env = dict(extra_env or {})
    if doc is not None:
        env["ALES_ENTITLEMENTS"] = json.dumps(doc)
    return create_app("sqlite://", tokens=TOKENS, outbox_interval=0, env=env, **kw), env


def _source(tc, scope, tenant="t1", headers=T1):
    src = new_source(tenant, "doc", b"x", "kb", principal_scope=scope)
    assert tc.post("/v1/sources", json=src, headers=headers).status_code == 200
    return src["context_id"]


def _authorize(tc, cid, principal=None, tenant="t1", headers=T1, **extra):
    body = {"tenant_id": tenant, "principal": principal or PRINCIPAL, "purpose": "rag",
            "objects": [{"context_id": cid}], **extra}
    return tc.post("/v1/authorize", json=body, headers=headers)


def _audits(tc, action, tenant="t1"):
    with tc.app.state.session_factory() as s:
        return [r.detail for r in s.scalars(select(AuditLog).where(AuditLog.tenant_id == tenant, AuditLog.action == action))]


# ---------------------------------------------------------------------------------- static entitlements
def test_group_scope_allows_via_server_resolved_groups_and_audits_revision():
    app, _ = _app({"t1": {"alice": ["eng"]}})
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        r = _authorize(tc, cid)
        assert r.json()["decision"] == "ALLOW"
        carol = _authorize(tc, cid, principal={"type": "user", "id": "carol"})
        assert carol.json()["decision"] == "DENY"
        d = _audits(tc, "decision.authorize")
        allow = next(x for x in d if x["decision"] == "ALLOW")["policy"]
        assert allow["entitlement_status"] == "resolved" and allow["groups"] == ["eng"]
        assert allow["entitlement_sources"] == ["static"] and len(allow["entitlement_revision"]) == 64
        assert allow["entitlement_authority"] == ["event-maintained"]
        none = next(x for x in d if x["decision"] == "DENY")["policy"]
        assert none["entitlement_revision"] == allow["entitlement_revision"]  # per-tenant document revision


def test_caller_supplied_groups_are_rejected_when_a_provider_is_configured():
    app, _ = _app({"t1": {}})
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        r = _authorize(tc, cid, groups=["eng"])
        assert r.status_code == 422 and "resolved by the server" in r.json()["detail"]
        rej = _audits(tc, "identity.groups_rejected")
        assert rej and rej[0]["reason"] == "caller_groups_with_provider"
        assert _authorize(tc, cid).json()["decision"] == "DENY"  # and no self-assertion leaked in


def test_without_provider_caller_groups_pass_through_and_are_flagged():
    app, _ = _app()
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        r = _authorize(tc, cid, groups=["eng"])
        assert r.json()["decision"] == "ALLOW"
        pol = _audits(tc, "decision.authorize")[0]["policy"]
        assert pol["entitlement_status"] == "caller_asserted" and pol["entitlement_sources"] == ["caller"]


def test_production_never_accepts_caller_groups():
    req = _req_model(groups=["eng"])
    with pytest.raises(CallerGroupsRejected):
        resolve_for_request(None, req, "t1", _ident(), production=True)
    out_req, out = resolve_for_request(None, req, "t1", _ident(), production=False)
    assert out.status == "caller_asserted" and out_req.groups == ["eng"]


def test_issuer_qualified_principal_through_the_api():
    app, _ = _app({"t1": {"iss:https://a/:alice": ["eng"], "alice": ["wrong-bare"]}})
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        qa = {"type": "user", "id": "alice", "issuer": "https://a/"}
        qb = {"type": "user", "id": "alice", "issuer": "https://b/"}
        assert _authorize(tc, cid, principal=qa).json()["decision"] == "ALLOW"
        assert _authorize(tc, cid, principal=qb).json()["decision"] == "DENY"
        assert _authorize(tc, cid).json()["decision"] == "DENY"  # the bare key is a different entry, no "eng"
        pol = next(x for x in _audits(tc, "decision.authorize") if x["decision"] == "ALLOW")["policy"]
        assert pol["principal_issuer"] == "https://a/"
        sid = _source(tc, ["iss:https://a/:alice"])
        assert _authorize(tc, sid, principal=qa).json()["decision"] == "ALLOW"
        assert _authorize(tc, sid, principal=qb).json()["decision"] == "DENY"


# --------------------------------------------------------------------------------------------- reload
def test_reload_group_removal_denies_and_bumps_epoch_only_for_changed_tenants():
    app, env = _app({"t1": {"alice": ["eng"]}, "t2": {"bob": ["ops"]}})
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        before = _authorize(tc, cid).json()
        assert before["decision"] == "ALLOW"
        t2_epoch = tc.get("/v1/snapshot", headers=bearer("tok-t2-all")).json()["revocation_epoch"]

        env["ALES_ENTITLEMENTS"] = json.dumps({"t1": {"alice": []}, "t2": {"bob": ["ops"]}})
        r = tc.post("/v1/entitlements/reload", headers=bearer("tok-t1-admin"))
        assert r.status_code == 200 and r.json()["tenant_changed"] is True
        assert r.json()["revocation_epoch"] == before["revocation_epoch"] + 1

        after = _authorize(tc, cid).json()
        assert after["decision"] == "DENY" and after["revocation_epoch"] == before["revocation_epoch"] + 1
        assert tc.get("/v1/snapshot", headers=bearer("tok-t2-all")).json()["revocation_epoch"] == t2_epoch
        assert _audits(tc, "entitlements.reload")[0]["revocation_epoch"] == after["revocation_epoch"]
        assert _audits(tc, "entitlements.reload", tenant="t2") == []

        # reload again with no change: no bump
        r2 = tc.post("/v1/entitlements/reload", headers=bearer("tok-t1-admin"))
        assert r2.json()["tenant_changed"] is False and r2.json()["revocation_epoch"] == after["revocation_epoch"]


def test_reload_bad_document_keeps_previous_and_requires_admin_and_a_source():
    app, env = _app({"t1": {"alice": ["eng"]}})
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        env["ALES_ENTITLEMENTS"] = "{not json"
        r = tc.post("/v1/entitlements/reload", headers=bearer("tok-t1-admin"))
        assert r.status_code == 422
        assert _authorize(tc, cid).json()["decision"] == "ALLOW"  # old doc still in force
        assert tc.post("/v1/entitlements/reload", headers=bearer("tok-t1-read")).status_code == 403
    app2, _ = _app()
    with TestClient(app2) as tc:
        assert tc.post("/v1/entitlements/reload", headers=bearer("tok-t1-admin")).status_code == 409


def test_reload_from_file(tmp_path):
    f = tmp_path / "ent.json"
    f.write_text(json.dumps({"t1": {"alice": ["eng"]}}), encoding="utf-8")
    app, _ = _app(extra_env={"ALES_ENTITLEMENTS_FILE": str(f)})
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        assert _authorize(tc, cid).json()["decision"] == "ALLOW"
        f.write_text(json.dumps({}), encoding="utf-8")
        assert tc.post("/v1/entitlements/reload", headers=bearer("tok-t1-admin")).json()["tenant_changed"] is True
        assert _authorize(tc, cid).json()["decision"] == "DENY"


def test_stale_group_decision_is_recomputed_if_membership_moves_mid_request():
    app, env = _app({"t1": {"alice": ["eng"]}})
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        static = app.state.entitlements_static
        real = static.resolve
        calls = {"n": 0}

        def flipping(tenant, pid, issuer, *, caller=None):
            calls["n"] += 1
            if calls["n"] == 3:  # after the first resolve inside _authorize: membership is removed
                env["ALES_ENTITLEMENTS"] = json.dumps({"t1": {"alice": []}})
                static.reload()
            return real(tenant, pid, issuer, caller=caller)

        static.resolve = flipping  # type: ignore[method-assign]
        r = _authorize(tc, cid).json()
        assert r["decision"] == "DENY"


# --------------------------------------------------------------------------------- failure semantics
class _Failing:
    authority_mode = "live-check"

    def __init__(self, required, name="dir"):
        self.required, self.name = required, name

    def resolve(self, tenant, principal_id, issuer, *, caller=None):
        raise EntitlementError("directory down")


class _Fixed:
    name, required, authority_mode = "fixed", True, "live-check"

    def __init__(self, groups, expires_at=None):
        self.groups, self.expires_at = tuple(groups), expires_at

    def resolve(self, tenant, principal_id, issuer, *, caller=None):
        return Entitlements(self.groups, "rev-1", self.expires_at, "fixed")


def test_required_provider_failure_is_unknown_not_allow_not_deny():
    app, _ = _app({"t1": {}})
    app.state.entitlements = EntitlementResolver([_Failing(True)])
    with TestClient(app) as tc:
        scoped = _source(tc, ["group:eng"])
        r = _authorize(tc, scoped).json()
        assert r["decision"] == "UNKNOWN" and r["reason"][0] == "ENTITLEMENT_UNAVAILABLE"
        # an object the principal is directly scoped to does not depend on groups: stays ALLOW
        direct = _source(tc, ["alice"])
        assert _authorize(tc, direct).json()["decision"] == "ALLOW"
        pol = next(x for x in _audits(tc, "decision.authorize") if x["decision"] == "UNKNOWN")["policy"]
        assert pol["entitlement_status"] == "unavailable" and pol["entitlement_failed"] == ["dir"]
        # a revoked object stays DENY (groups cannot help)
        rev = tc.post("/v1/revocations", json={"tenant_id": "t1", "source_id": scoped, "reason": "acl_changed"}, headers=T1)
        assert rev.status_code == 200
        assert _authorize(tc, scoped).json()["decision"] == "DENY"


def test_optional_provider_failure_means_no_groups_and_is_audited():
    app, _ = _app({"t1": {}})
    app.state.entitlements = EntitlementResolver([_Failing(False)])
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        r = _authorize(tc, cid).json()
        assert r["decision"] == "DENY" and r["reason"] == ["PRINCIPAL_NOT_IN_SCOPE"]
        pol = _audits(tc, "decision.authorize")[0]["policy"]
        assert pol["entitlement_status"] == "optional_unavailable"


def test_expires_at_caps_valid_until():
    app, _ = _app({"t1": {}})
    from datetime import UTC, datetime, timedelta

    exp = datetime.now(UTC) + timedelta(seconds=90)
    app.state.entitlements = EntitlementResolver([_Fixed(["eng"], exp)])
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        r = _authorize(tc, cid).json()
        assert r["decision"] == "ALLOW"
        assert r["valid_until"] == exp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        assert r["objects"][0]["valid_until"] == r["valid_until"]


# -------------------------------------------------------------------------------------- OIDC claim groups
GROUP_MAPPING = {"tenant_id": "org", "subject": "sub", "roles": "ales_roles", "groups": "groups"}


def _oidc_app(**cfg):
    return create_app("sqlite://", tokens=TOKENS, outbox_interval=0,
                      env={"ALES_OIDC_CONFIG": config(claim_mapping=GROUP_MAPPING, **cfg)})


def test_oidc_groups_apply_only_to_the_token_subject_and_cap_at_exp():
    app = _oidc_app()
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        exp = time.time() + 600
        user = mint(claims(sub="alice", groups=["eng"], exp=exp))
        r = _authorize(tc, cid, headers=bearer(user)).json()
        assert r["decision"] == "ALLOW"
        assert r["valid_until"].startswith(time.strftime("%Y-%m-%dT%H:%M:", time.gmtime(exp))[:14])
        pol = _audits(tc, "decision.authorize")[0]["policy"]
        assert pol["entitlement_sources"] == ["oidc-claim"] and pol["entitlement_authority"] == ["bounded-assertion"]
        # a service token for someone else cannot vouch for that person's groups
        svc = mint(claims(sub="svc", groups=["eng"]))
        other = _authorize(tc, cid, principal={"type": "user", "id": "bob"}, headers=bearer(svc)).json()
        assert other["decision"] == "DENY"
        # a different issuer asserted for the same subject is not the token's issuer
        wrong = _authorize(tc, cid, principal={"type": "user", "id": "alice", "issuer": "https://evil/"},
                           headers=bearer(user)).json()
        assert wrong["decision"] == "DENY"
        ok = _authorize(tc, cid, principal={"type": "user", "id": "alice", "issuer": ISS}, headers=bearer(user)).json()
        assert ok["decision"] == "ALLOW"


def test_oidc_group_overage_is_unknown_and_malformed_claim_is_401():
    app = _oidc_app()
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        overage = mint(claims(sub="alice", _claim_names={"groups": "src1"}))
        r = _authorize(tc, cid, headers=bearer(overage)).json()
        assert r["decision"] == "UNKNOWN" and "ENTITLEMENT_UNAVAILABLE" in r["reason"]
        assert _authorize(tc, cid, headers=bearer(mint(claims(sub="alice", groups="eng")))).status_code == 401
        none = mint(claims(sub="alice"))  # no groups claim = no groups
        assert _authorize(tc, cid, headers=bearer(none)).json()["decision"] == "DENY"
    optional = _oidc_app(groups_required=False)
    with TestClient(optional) as tc:
        cid = _source(tc, ["group:eng"])
        overage = mint(claims(sub="alice", _claim_names={"groups": "src1"}))
        r = _authorize(tc, cid, headers=bearer(overage)).json()
        assert r["decision"] == "DENY" and "ENTITLEMENT_UNAVAILABLE" not in r["reason"]


def test_oidc_config_validation():
    with pytest.raises(ConfigError):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0,
                   env={"ALES_OIDC_CONFIG": config(claim_mapping={**GROUP_MAPPING, "groups": ""})})
    with pytest.raises(ConfigError):
        create_app("sqlite://", tokens=TOKENS, outbox_interval=0,
                   env={"ALES_OIDC_CONFIG": config(claim_mapping=GROUP_MAPPING, groups_required="yes")})
    assert AUD  # (imported for the shared config helpers)


# ---------------------------------------------------------------------------------------------- units
def test_static_document_validation_and_per_tenant_revisions():
    with pytest.raises(ConfigError):
        StaticEntitlements.from_env({"ALES_ENTITLEMENTS": "[]"})
    with pytest.raises(ConfigError):
        StaticEntitlements.from_env({"ALES_ENTITLEMENTS": '{"t":{"a":[""]}}'})
    with pytest.raises(ConfigError):
        StaticEntitlements.from_env({"ALES_ENTITLEMENTS": "{}", "ALES_ENTITLEMENTS_FILE": "x"})
    assert StaticEntitlements.from_env({}) is None
    env = {"ALES_ENTITLEMENTS": json.dumps({"t1": {"a": ["x"]}, "t2": {"b": ["y"]}})}
    s = StaticEntitlements.from_env(env)
    r1, r2 = s.revision_for("t1"), s.revision_for("t2")
    assert r1 != r2 and s.resolve("t1", "a", None).groups == ("x",)
    env["ALES_ENTITLEMENTS"] = json.dumps({"t1": {"a": ["x", "z"]}, "t2": {"b": ["y"]}})
    assert s.reload() == frozenset({"t1"}) and s.revision_for("t2") == r2 and s.revision_for("t1") != r1
    env["ALES_ENTITLEMENTS"] = json.dumps({"t2": {"b": ["y"]}})  # t1 removed entirely
    assert s.reload() == frozenset({"t1"}) and s.resolve("t1", "a", None).groups == ()


def test_resolver_unions_providers_and_flags_failures():
    res = EntitlementResolver([_Fixed(["a"]), _Fixed(["b"]), _Failing(False)])
    out = res.resolve("t", "p", None, None)
    assert out.groups == ("a", "b") and out.status == "optional_unavailable" and out.failed == ("dir",)
    assert EntitlementResolver([_Failing(True)]).resolve("t", "p", None, None).unavailable
    assert EntitlementResolver([]).resolve("t", "p", None, None).status == "none"


def test_sdk_issuer_kwarg_is_sent_and_bypasses_the_cache():
    app, _ = _app({"t1": {"iss:https://a/:alice": ["eng"]}})
    with TestClient(app) as tc:
        cid = _source(tc, ["group:eng"])
        transport = TestClientTransport(tc)
        client = InvariantClient("http://testserver", "t1", "tok-t1-all", transport=transport)
        r1 = client.authorize(PRINCIPAL, "rag", [cid], issuer="https://a/")
        assert r1.decision == "ALLOW" and not r1.from_cache
        r2 = client.authorize(PRINCIPAL, "rag", [cid], issuer="https://a/")
        assert not r2.from_cache  # issuer-bearing requests are never cached (the cache key has no issuer)
        assert client.authorize({**PRINCIPAL, "issuer": "https://b/"}, "rag", [cid]).decision == "DENY"


# helpers for the unit test above
def _req_model(groups):
    from ales_core import AuthorizeRequest, ObjectRef, Principal

    return AuthorizeRequest(
        tenant_id="t1", principal=Principal(type="user", id="alice"), purpose="rag",
        objects=[ObjectRef(context_id="c")], groups=groups,
    )


def _ident():
    from ales_server.auth import Identity

    return Identity("svc", "t1", frozenset({"read"}))


_ = EntitlementOutcome  # re-exported name kept importable
