import json

import pytest
from ales_connectors import ConnectorRegistry, FileCheckpoint, S3Connector, WebhookConnector, sign_body
from connectors_fixtures import reasons
from test_spi_diff import FakeRemote  # same directory (rootdir/conftest puts tests dir on sys.path)


def _fake(client, cid, clock, interval=30):
    f = FakeRemote(client, "t1", cid, poll_interval_seconds=interval, clock=clock)
    return f


def test_run_all_once_scans_and_watches(client, server, clock):
    reg = ConnectorRegistry(clock=clock)
    a, b = _fake(client, "a", clock), _fake(client, "b", clock)
    a.put("x", b"1")
    b.put("y", b"2")
    reg.register(a)
    reg.register(b)
    res = reg.run_all_once()
    assert [r.connector_id for r in res] == ["a", "b"] and all(r.ok for r in res)
    assert sum(len(r.registered) for r in res) == 2
    del a.store["x"]
    b.put("y", b"3")
    res = {r.connector_id: r for r in reg.run_all_once()}
    assert reasons(res["a"].events) == ["deleted"] and reasons(res["b"].events) == ["version_superseded"]


def test_duplicate_id_rejected(client, clock):
    reg = ConnectorRegistry()
    reg.register(_fake(client, "a", clock))
    with pytest.raises(ValueError):
        reg.register(_fake(client, "a", clock))


def test_failure_isolated_and_reported(client, server, clock):
    reg = ConnectorRegistry(clock=clock)
    bad, good = _fake(client, "bad", clock), _fake(client, "good", clock)
    good.put("x", b"1")
    bad.fail = True
    reg.register(bad)
    reg.register(good)
    res = {r.connector_id: r for r in reg.run_all_once()}
    assert not res["bad"].ok and "remote down" in res["bad"].error
    assert res["good"].ok and len(res["good"].registered) == 1
    rep = reg.health_report()
    assert rep["status"] == "degraded" and rep["degraded"] == ["bad"]
    bad.fail = False
    reg.run_all_once()
    assert reg.health_report()["status"] == "ok"


def test_health_aggregation_lag_coverage_staleness(client, clock):
    reg = ConnectorRegistry(clock=clock)
    a = _fake(client, "a", clock, interval=10)
    a.put("x", b"1")
    reg.register(a)
    wh = WebhookConnector(client, "t1", shared_secret="s", clock=clock)
    reg.register(wh)
    assert "never synced" in reg.health_report()["connectors"]["a"]["problems"]
    reg.run_all_once()
    clock.t += 5
    rep = reg.health_report()
    assert rep["status"] == "ok" and rep["worst_lag_seconds"] == pytest.approx(5)
    assert rep["connector_count"] == 2
    assert rep["coverage"] == {"deleted": True, "version_superseded": True, "acl_changed": True}
    assert rep["connectors"]["webhook"]["mode"] == "events"
    clock.t += 100  # > 3x the 10s SLA
    rep = reg.health_report()
    assert rep["status"] == "degraded" and "stale" in rep["connectors"]["a"]["problems"][0]
    assert json.dumps(rep)  # JSON-serialisable for an API/cron log


def test_coverage_is_intersection(client, clock):
    reg = ConnectorRegistry(clock=clock)
    a = _fake(client, "a", clock)
    a.coverage = {**a.coverage, "acl_changed": False}
    reg.register(a)
    reg.register(_fake(client, "b", clock))
    assert reg.health_report()["coverage"]["acl_changed"] is False


def test_mixed_real_connectors_share_one_checkpoint_file(client, server, clock, tmp_path):
    import boto3
    from moto import mock_aws

    ck = FileCheckpoint(tmp_path / "shared.json")
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
        s3.create_bucket(Bucket="bkt")
        s3.put_object(Bucket="bkt", Key="k", Body=b"1")
        reg = ConnectorRegistry(clock=clock)
        reg.register(S3Connector(client, "t1", "bkt", s3_client=s3, checkpoint=ck, clock=clock))
        reg.register(WebhookConnector(client, "t1", shared_secret="s", checkpoint=ck, clock=clock))
        reg.run_all_once()
        body = {"action": "updated", "object_id": "w", "version": "1", "timestamp": clock.t}
        rb = json.dumps(body).encode()
        reg.get("webhook").handle(body, signature_header=sign_body(rb, "s"), raw_body=rb)  # type: ignore[attr-defined]
        data = json.loads((tmp_path / "shared.json").read_text())
        assert {"s3:bkt/:state", "webhook:state"} <= set(data)
        assert "k" in data["s3:bkt/:state"] and "w" in data["webhook:state"]
        assert reg.health_report()["status"] == "ok"


def _synced_registry(client, clock, **kw):
    from ales_connectors import ConnectorRegistry

    reg = ConnectorRegistry(clock=clock, **kw)
    for cid in ("a", "b"):
        f = _fake(client, cid, clock, interval=10)
        f.put("x", b"1")
        reg.register(f)
    reg.run_all_once()
    return reg


def test_assert_fresh_ok(client, server, clock):
    from ales_connectors import FreshnessPolicy, freshness_guard

    reg = _synced_registry(client, clock)
    clock.t += 5
    reg.assert_fresh(policy=FreshnessPolicy(60))
    assert freshness_guard(reg, policy=FreshnessPolicy(60))() == []


def test_assert_fresh_raises_with_ids(client, server, clock):
    from ales_connectors import FreshnessPolicy, StaleConnectorError, freshness_guard

    reg = _synced_registry(client, clock)
    clock.t += 120
    with pytest.raises(StaleConnectorError) as ei:
        reg.assert_fresh(policy=FreshnessPolicy(60))
    assert ei.value.connector_ids == ["a", "b"] and "exceeds" in str(ei.value)
    reg.assert_fresh(["a"], policy=FreshnessPolicy(600))  # lenient policy passes
    assert freshness_guard(reg, ["b"], policy=FreshnessPolicy(60))() == ["b"]
    # default (no policy): 3x the 10s SLA = 30s
    with pytest.raises(StaleConnectorError):
        reg.assert_fresh()


def test_never_synced_and_failed_and_unknown_are_stale(client, server, clock):
    from ales_connectors import ConnectorRegistry, FreshnessPolicy, StaleConnectorError

    reg = ConnectorRegistry(clock=clock, freshness=FreshnessPolicy(60))
    reg.register(_fake(client, "never", clock))
    with pytest.raises(StaleConnectorError) as ei:
        reg.assert_fresh()
    assert ei.value.stale["never"] == "never synced"
    bad = _fake(client, "bad", clock)
    bad.fail = True
    reg.register(bad)
    reg.run_all_once()
    assert "last run failed" in reg.stale_connectors(["bad"])["bad"]
    assert reg.stale_connectors(["ghost"]) == {"ghost": "unknown connector"}


def test_per_connector_override(client, server, clock):
    from ales_connectors import FreshnessPolicy

    reg = _synced_registry(client, clock)
    clock.t += 120
    pol = FreshnessPolicy(60, overrides={"a": 600})
    assert list(reg.stale_connectors(policy=pol)) == ["b"]
    reg.assert_fresh(["a"], policy=pol)
