import hashlib
import json

import boto3
import pytest
from ales_connectors import S3Connector
from botocore.exceptions import ClientError
from connectors_fixtures import reasons, revocations
from moto import mock_aws

BUCKET = "ales-test"


@pytest.fixture
def s3():
    with mock_aws():
        c = boto3.client("s3", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
        c.create_bucket(Bucket=BUCKET)
        yield c


def _acl(s3, key, **acl):
    s3.put_object(Bucket=BUCKET, Key=key + ".acl.json", Body=json.dumps(acl).encode())


def _conn(client, s3, **kw):
    return S3Connector(client, "t1", BUCKET, s3_client=s3, **kw)


def test_scan_registers_with_sidecar_acl_and_prefix(client, server, s3):
    s3.put_object(Bucket=BUCKET, Key="docs/a.txt", Body=b"alpha")
    s3.put_object(Bucket=BUCKET, Key="docs/b.txt", Body=b"beta")
    _acl(s3, "docs/b.txt", classification="confidential", principal_scope=["alice"], purpose_scope=["support"])
    s3.put_object(Bucket=BUCKET, Key="other/c.txt", Body=b"outside prefix")
    c = _conn(client, s3, prefix="docs/")
    by = {e["object_id"]: e for e in c.scan()}
    assert set(by) == {"docs/a.txt", "docs/b.txt"}  # sidecars and out-of-prefix objects excluded
    assert by["docs/a.txt"]["classification"] == "internal"
    assert by["docs/b.txt"]["classification"] == "confidential"
    assert by["docs/b.txt"]["principal_scope"] == ["alice"]
    assert by["docs/a.txt"]["source_system"] == "s3"
    assert c.scan() == [] and c.watch_once() == []


def test_default_classification_config(client, s3):
    s3.put_object(Bucket=BUCKET, Key="a", Body=b"x")
    _acl(s3, "a", principal_scope=["alice"])  # partial sidecar inherits configured default classification
    s3.put_object(Bucket=BUCKET, Key="b", Body=b"y")
    envs = {e["object_id"]: e for e in _conn(client, s3, default_classification="confidential").scan()}
    assert envs["a"]["classification"] == "confidential" and envs["a"]["principal_scope"] == ["alice"]
    assert envs["b"]["classification"] == "confidential"


def test_pagination_over_1000_keys(client, s3):
    for i in range(1005):
        s3.put_object(Bucket=BUCKET, Key=f"k/{i:05d}", Body=b"x")
    assert len(_conn(client, s3).scan()) == 1005


def test_overwrite_supersedes_and_delete_revokes(client, server, s3):
    s3.put_object(Bucket=BUCKET, Key="a", Body=b"v1")
    c = _conn(client, s3)
    (old,) = c.scan()
    s3.put_object(Bucket=BUCKET, Key="a", Body=b"v2")
    evs = c.watch_once()
    assert reasons(evs) == ["version_superseded"] and evs[0]["source_id"] == old["context_id"]
    assert c.watch_once() == []
    s3.delete_object(Bucket=BUCKET, Key="a")
    evs = c.watch_once()
    assert reasons(evs) == ["deleted"]
    assert len(revocations(server)) == 2


def test_acl_sidecar_narrow_and_widen(client, server, s3):
    s3.put_object(Bucket=BUCKET, Key="a", Body=b"x")
    _acl(s3, "a", classification="internal")
    c = _conn(client, s3)
    c.scan()
    _acl(s3, "a", classification="restricted")
    assert reasons(c.watch_once()) == ["acl_changed"]
    _acl(s3, "a", classification="internal")  # widen: silent
    assert c.watch_once() == []
    assert len(revocations(server)) == 1
    # sidecar removed -> default (internal): unchanged vs current -> nothing
    s3.delete_object(Bucket=BUCKET, Key="a.acl.json")
    assert c.watch_once() == []


def test_corrupt_sidecar_fails_closed(client, server, s3):
    s3.put_object(Bucket=BUCKET, Key="a", Body=b"x")
    c = _conn(client, s3)
    c.scan()
    s3.put_object(Bucket=BUCKET, Key="a.acl.json", Body=b"{garbage")
    assert reasons(c.watch_once()) == ["acl_changed"]
    env = list(server.envelopes.values())[-1]
    assert env["classification"] == "restricted" and env["principal_scope"] == []


def test_checkpoint_restart_no_reemit(client, server, s3, tmp_path):
    from ales_connectors import FileCheckpoint

    s3.put_object(Bucket=BUCKET, Key="a", Body=b"x")
    _conn(client, s3, checkpoint=FileCheckpoint(tmp_path / "c.json")).scan()
    c2 = _conn(client, s3, checkpoint=FileCheckpoint(tmp_path / "c.json"))
    assert c2.watch_once() == [] and revocations(server) == []


def test_listing_failure_never_emits_deletes(client, server, s3):
    s3.put_object(Bucket=BUCKET, Key="a", Body=b"x")
    c = _conn(client, s3)
    c.scan()
    c.bucket = "no-such-bucket"
    with pytest.raises(ClientError):
        c.watch_once()
    assert revocations(server) == [] and c.health().errors


# -- versioned buckets ------------------------------------------------------------------------------
def test_versioned_bucket_hint_includes_version_id_and_delete_marker(client, server, s3):
    s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
    r1 = s3.put_object(Bucket=BUCKET, Key="a", Body=b"v1")
    c = _conn(client, s3)
    c.scan()
    assert c.state["a"]["hint"].endswith("|" + r1["VersionId"])
    s3.put_object(Bucket=BUCKET, Key="a", Body=b"v2")
    assert reasons(c.watch_once()) == ["version_superseded"]
    s3.delete_object(Bucket=BUCKET, Key="a")  # creates a delete marker; old versions still exist
    assert reasons(c.watch_once()) == ["deleted"]


# -- digest modes ----------------------------------------------------------------------------------
def _multipart(s3, key, parts):
    up = s3.create_multipart_upload(Bucket=BUCKET, Key=key)
    done = []
    for i, body in enumerate(parts, 1):
        r = s3.upload_part(Bucket=BUCKET, Key=key, UploadId=up["UploadId"], PartNumber=i, Body=body)
        done.append({"ETag": r["ETag"], "PartNumber": i})
    s3.complete_multipart_upload(
        Bucket=BUCKET, Key=key, UploadId=up["UploadId"], MultipartUpload={"Parts": done}
    )


def test_single_part_uses_etag_mode(client, s3):
    s3.put_object(Bucket=BUCKET, Key="a", Body=b"x")
    c = _conn(client, s3)
    c.scan()
    assert c.state["a"]["digest_mode"] == "etag"
    assert "etag" in c.health().details["digest_modes"]


def test_multipart_small_streams_real_sha256(client, s3):
    parts = [b"a" * 5 * 1024 * 1024, b"tail"]
    _multipart(s3, "big", parts)
    c = _conn(client, s3)
    (env,) = c.scan()
    assert c.state["big"]["digest_mode"] == "sha256"
    assert env["content_digest"] == "sha256:" + hashlib.sha256(b"".join(parts)).hexdigest()
    # unchanged on re-poll, no re-stream needed
    assert c.watch_once() == []


def test_multipart_over_cap_falls_back_to_opaque_etag(client, s3):
    _multipart(s3, "big", [b"a" * 5 * 1024 * 1024, b"tail"])
    c = _conn(client, s3, multipart_hash_max_bytes=1024)
    c.scan()
    assert c.state["big"]["digest_mode"] == "etag"
    assert c.watch_once() == []
    # same bytes re-uploaded with different part boundaries -> different multipart ETag -> supersession
    # (documented: spurious but safe direction)
    _multipart(s3, "big", [b"a" * 6 * 1024 * 1024, b"a" * 0 + b"tail"[:4]])
    assert reasons(c.watch_once()) == ["version_superseded"]


# -- event mode -----------------------------------------------------------------------------------------
def _rec(name, key, bucket=BUCKET):
    return {"eventName": name, "s3": {"bucket": {"name": bucket}, "object": {"key": key}}}


def test_event_records_created_overwritten_removed(client, server, s3):
    c = _conn(client, s3, event_mode=True)
    assert c.health().mode == "events"
    s3.put_object(Bucket=BUCKET, Key="my docs/a+b.txt", Body=b"v1")
    # keys in classic notifications are URL-encoded (space -> '+')
    assert c.apply_event_record(_rec("ObjectCreated:Put", "my+docs/a%2Bb.txt")) == []
    assert "my docs/a+b.txt" in c.state
    s3.put_object(Bucket=BUCKET, Key="my docs/a+b.txt", Body=b"v2")
    evs = c.apply_event_record(_rec("ObjectCreated:Put", "my+docs/a%2Bb.txt"))
    assert reasons(evs) == ["version_superseded"]
    # duplicate delivery converges (state re-read): no new events
    assert c.apply_event_record(_rec("ObjectCreated:Put", "my+docs/a%2Bb.txt")) == []
    s3.delete_object(Bucket=BUCKET, Key="my docs/a+b.txt")
    evs = c.apply_event_record(_rec("ObjectRemoved:Delete", "my+docs/a%2Bb.txt"))
    assert reasons(evs) == ["deleted"]
    assert c.apply_event_record(_rec("ObjectRemoved:Delete", "my+docs/a%2Bb.txt")) == []


def test_event_eventbridge_shape_and_sidecar_event(client, s3):
    s3.put_object(Bucket=BUCKET, Key="a", Body=b"x")
    c = _conn(client, s3, event_mode=True)
    eb = {"detail-type": "Object Created", "detail": {"bucket": {"name": BUCKET}, "object": {"key": "a"}}}
    assert c.apply_event_record(eb) == []
    assert "a" in c.state
    _acl(s3, "a", classification="restricted")
    side = {"detail-type": "Object Created", "detail": {"bucket": {"name": BUCKET}, "object": {"key": "a.acl.json"}}}
    assert reasons(c.apply_event_record(side)) == ["acl_changed"]
    assert c.apply_event_record({**eb, "detail-type": "Object Deleted"}) == []  # stale event: object still there
    s3.delete_object(Bucket=BUCKET, Key="a")
    gone = {"detail-type": "Object Deleted", "detail": {"bucket": {"name": BUCKET}, "object": {"key": "a"}}}
    assert reasons(c.apply_event_record(gone)) == ["deleted"]


def test_event_ignores_foreign_bucket_prefix_and_garbage(client, s3):
    s3.put_object(Bucket=BUCKET, Key="x/a", Body=b"x")
    c = _conn(client, s3, prefix="docs/", event_mode=True)
    assert c.apply_event_record(_rec("ObjectCreated:Put", "x/a")) == []
    assert c.apply_event_record(_rec("ObjectCreated:Put", "docs/a", bucket="other")) == []
    assert c.apply_event_record({"nonsense": 1}) == []
    assert c.apply_event_record({"s3": {}}) == []
    assert c.state == {}
    assert c.health().errors  # the malformed record was surfaced


# -- connector digest_mode (R32) -----------------------------------------------------------------------------
def test_invalid_digest_mode_rejected(client, s3):
    with pytest.raises(ValueError):
        _conn(client, s3, digest_mode="md5")


def test_content_mode_hashes_everything_even_over_cap(client, s3):
    parts = [b"a" * 5 * 1024 * 1024, b"tail"]
    _multipart(s3, "big", parts)
    s3.put_object(Bucket=BUCKET, Key="small", Body=b"x")
    c = _conn(client, s3, digest_mode="content", multipart_hash_max_bytes=1024)
    envs = {e["object_id"]: e for e in c.scan()}
    assert envs["big"]["content_digest"] == "sha256:" + hashlib.sha256(b"".join(parts)).hexdigest()
    assert envs["small"]["content_digest"] == "sha256:" + hashlib.sha256(b"x").hexdigest()
    assert {v["digest_mode"] for v in c.state.values()} == {"sha256"}
    d = c.health().details
    assert d["etag_mode_objects"] == 0 and d["configured_digest_mode"] == "content"
    assert c.watch_once() == []


def test_auto_counts_kms_objects_as_opaque_etag(client, s3):
    s3.put_object(Bucket=BUCKET, Key="plain", Body=b"x")
    s3.put_object(Bucket=BUCKET, Key="kms", Body=b"y", ServerSideEncryption="aws:kms")
    c = _conn(client, s3)
    c.scan()
    assert c.state["kms"]["digest_mode"] == "etag-opaque"
    assert c.state["plain"]["digest_mode"] == "etag"
    d = c.health().details
    assert d["etag_mode_objects"] == 2 and d["etag_opaque_encrypted_objects"] == 1


def test_content_mode_streams_kms_objects(client, s3):
    s3.put_object(Bucket=BUCKET, Key="kms", Body=b"y", ServerSideEncryption="aws:kms")
    c = _conn(client, s3, digest_mode="content")
    (env,) = c.scan()
    assert env["content_digest"] == "sha256:" + hashlib.sha256(b"y").hexdigest()
    assert c.health().details["etag_mode_objects"] == 0


def test_etag_mode_never_streams(client, s3):
    _multipart(s3, "big", [b"a" * 5 * 1024 * 1024, b"tail"])
    c = _conn(client, s3, digest_mode="etag")
    c.scan()
    assert c.state["big"]["digest_mode"] == "etag"
