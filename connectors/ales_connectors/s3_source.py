"""Amazon S3 source connector (polling, with optional event-driven refresh).

Polling: lists the bucket under ``prefix`` (``list_objects_v2`` or, for versioned buckets,
``list_object_versions`` so the VersionId joins the version hint and delete markers count as deletes).

Digest modes (see ``RemoteObject.metadata['digest_mode']``):

* ``etag``   -- the envelope ``content_digest`` is sha256 of the object's ETag identity, NOT of its bytes.
                Used for every object whose bytes we do not stream. A single-part, non-KMS ETag is the
                MD5 of the content so it is a faithful change detector; for MULTIPART uploads the ETag is
                ``md5(md5(part1)+...)-N`` and depends on part boundaries: the same bytes uploaded with a
                different part size produce a different ETag (a spurious ``version_superseded``, which is
                the safe direction), and SSE-KMS/SSE-C ETags are not content hashes at all.
* ``sha256`` -- multipart objects with ``size <= multipart_hash_max_bytes`` are streamed once (only when
                their hint changed) and hashed, giving a real content digest. Larger ones stay in ``etag``
                mode.

Connector-level ``digest_mode`` (constructor argument):

* ``"auto"``    (default) -- the behaviour above. Additionally, objects encrypted with SSE-KMS or SSE-C are
                 recorded with mode ``etag-opaque`` (their ETag is not a content hash, so an in-place content
                 change may go undetected) and are counted in ``health().details["etag_mode_objects"]`` so
                 operators can see the exposure. Detection costs one ``head_object`` per object whose
                 version hint changed (never per poll for unchanged objects).
* ``"content"`` -- EVERY object is streamed and sha256-hashed regardless of size or encryption; the
                 ``multipart_hash_max_bytes`` cap is ignored. COST: one full GET (egress + request charges +
                 KMS decrypt calls) per new or changed object, bandwidth proportional to object size, and
                 first-scan time proportional to bucket bytes. Unchanged objects (same ETag/VersionId hint)
                 are not re-streamed. Use for buckets where KMS/SSE-C or oversized objects hold protected data.
* ``"etag"``    -- never stream; every object uses the ETag identity (cheapest, weakest).

ACLs come from the sidecar object ``<key>.acl.json`` (same schema as the filesystem connector), else the
configured default classification. Native S3 ACL / bucket-policy changes are NOT observed (coverage note).

Event mode: ``apply_event_record`` accepts S3 notification records (SQS/SNS/Lambda ``Records`` shape) or
EventBridge envelopes (``detail-type`` + ``detail``) and refreshes just the affected object, so revocation
latency drops from the poll interval to the event delivery latency. Keep a periodic ``watch_once`` as the
reconcile loop: notifications are at-least-once but can be lost, and we do not assume infrastructure.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import unquote_plus

from ales_sdk.client import InvariantClient

from .spi import (
    ACL_SUFFIX,
    DEFAULT_ACL,
    CheckpointStore,
    ConnectorHealth,
    PollingConnector,
    RemoteObject,
    RevocationEvent,
    parse_acl_sidecar,
    sidecar_key,
)

DEFAULT_MULTIPART_HASH_MAX_BYTES = 8 * 1024 * 1024
DIGEST_MODES = ("auto", "content", "etag")
_ETAG_FAMILY = ("etag", "etag-opaque")


def _etag_digest(etag: str) -> str:
    return hashlib.sha256(f"s3-etag:{etag}".encode()).hexdigest()


class S3Connector(PollingConnector):
    source_system = "s3"
    actor = "ales-s3-connector"

    def __init__(
        self,
        client: InvariantClient,
        tenant_id: str,
        bucket: str,
        *,
        s3_client: Any | None = None,
        prefix: str = "",
        connector_id: str | None = None,
        checkpoint: CheckpointStore | None = None,
        poll_interval_seconds: float = 60.0,
        default_classification: str = "internal",
        multipart_hash_max_bytes: int = DEFAULT_MULTIPART_HASH_MAX_BYTES,
        event_mode: bool = False,
        digest_mode: str = "auto",
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(
            client,
            tenant_id,
            connector_id or f"s3:{bucket}/{prefix}",
            checkpoint,
            poll_interval_seconds=poll_interval_seconds,
            clock=clock,
        )
        if digest_mode not in DIGEST_MODES:
            raise ValueError(f"digest_mode must be one of {DIGEST_MODES}, got {digest_mode!r}")
        self.digest_mode = digest_mode
        if s3_client is None:
            import boto3  # deferred: optional dependency

            s3_client = boto3.client("s3")
        self.s3 = s3_client
        self.bucket = bucket
        self.prefix = prefix
        self.default_acl = {**DEFAULT_ACL, "classification": default_classification}
        self.multipart_hash_max_bytes = multipart_hash_max_bytes
        self.mode = "events" if event_mode else "polling"
        self._sidecar_cache: dict[str, tuple[str, dict[str, Any]]] = {}  # sidecar key -> (etag, acl)

    # -- listing -------------------------------------------------------------------------------------
    def _is_versioned(self) -> bool:
        resp = self.s3.get_bucket_versioning(Bucket=self.bucket)
        return bool(resp.get("Status") in ("Enabled", "Suspended"))

    def _raw_listing(self) -> list[dict[str, Any]]:
        """Current (latest, non-delete-marker) entries as dicts with Key/ETag/Size/VersionId."""
        out: list[dict[str, Any]] = []
        if self._is_versioned():
            pager = self.s3.get_paginator("list_object_versions")
            for page in pager.paginate(Bucket=self.bucket, Prefix=self.prefix):
                for v in page.get("Versions", []):
                    if v.get("IsLatest"):
                        out.append(v)
                # Delete markers are deliberately skipped: a latest delete marker == object gone.
        else:
            pager = self.s3.get_paginator("list_objects_v2")
            for page in pager.paginate(Bucket=self.bucket, Prefix=self.prefix):
                out.extend(page.get("Contents", []))
        return out

    def _acl_for(self, key: str, sidecars: dict[str, dict[str, Any]]) -> dict[str, Any]:
        sk = sidecar_key(key)
        side = sidecars.get(sk)
        if side is None:
            return dict(self.default_acl)
        etag = side["ETag"]
        cached = self._sidecar_cache.get(sk)
        if cached is None or cached[0] != etag:
            params: dict[str, Any] = {"Bucket": self.bucket, "Key": sk}
            if side.get("VersionId") and side["VersionId"] != "null":
                params["VersionId"] = side["VersionId"]
            body = self.s3.get_object(**params)["Body"].read()
            cached = (etag, parse_acl_sidecar(body, self.default_acl))
            self._sidecar_cache[sk] = cached
        return dict(cached[1])

    def _to_remote(self, entry: dict[str, Any], acl: dict[str, Any]) -> RemoteObject:
        etag = str(entry["ETag"]).strip('"')
        vid = entry.get("VersionId")
        hint = etag if not vid or vid == "null" else f"{etag}|{vid}"
        multipart = "-" in etag
        return RemoteObject(
            id=entry["Key"],
            version_hint=hint,
            digest=None,
            acl=acl,
            metadata={
                "etag": etag,
                "version_id": vid,
                "size": entry.get("Size"),
                "multipart": multipart,
            },
        )

    def list_objects(self) -> list[RemoteObject]:
        entries = self._raw_listing()
        sidecars = {e["Key"]: e for e in entries if e["Key"].endswith(ACL_SUFFIX)}
        out = []
        for e in entries:
            if e["Key"].endswith(ACL_SUFFIX):
                continue
            out.append(self._to_remote(e, self._acl_for(e["Key"], sidecars)))
        return out

    # -- digest --------------------------------------------------------------------------------------
    def _stream_sha256(self, obj: RemoteObject) -> str:
        md = obj.metadata
        params: dict[str, Any] = {"Bucket": self.bucket, "Key": obj.id}
        if md.get("version_id") and md["version_id"] != "null":
            params["VersionId"] = md["version_id"]
        h = hashlib.sha256()
        body = self.s3.get_object(**params)["Body"]
        for chunk in iter(lambda: body.read(1024 * 1024), b""):
            h.update(chunk)
        return h.hexdigest()

    def _is_opaque_encrypted(self, obj: RemoteObject) -> bool:
        """True if the ETag is not a content hash (SSE-KMS / DSSE-KMS / SSE-C). One HEAD, lazily."""
        md = obj.metadata
        params: dict[str, Any] = {"Bucket": self.bucket, "Key": obj.id}
        if md.get("version_id") and md["version_id"] != "null":
            params["VersionId"] = md["version_id"]
        head = self.s3.head_object(**params)
        sse = str(head.get("ServerSideEncryption") or "")
        return sse.startswith("aws:kms") or bool(head.get("SSECustomerAlgorithm"))

    def resolve_digest(self, obj: RemoteObject) -> tuple[str, str]:
        md = obj.metadata
        if self.digest_mode == "content":
            return self._stream_sha256(obj), "sha256"
        if self.digest_mode == "etag":
            return _etag_digest(md["etag"]), "etag"
        if md.get("multipart") and (md.get("size") or 0) <= self.multipart_hash_max_bytes:
            return self._stream_sha256(obj), "sha256"
        if self._is_opaque_encrypted(obj):
            return _etag_digest(md["etag"]), "etag-opaque"
        return _etag_digest(md["etag"]), "etag"

    # -- event mode ----------------------------------------------------------------------------------
    @staticmethod
    def _parse_record(record: dict[str, Any]) -> tuple[str, str, str | None] | None:
        """Return (bucket, key, 'created'|'removed') or None if not an object event we understand."""
        if "s3" in record:  # classic notification record
            name = str(record.get("eventName", ""))
            kind = "removed" if name.startswith("ObjectRemoved") else "created" if name.startswith("ObjectCreated") else None
            s3 = record["s3"]
            return s3["bucket"]["name"], unquote_plus(s3["object"]["key"]), kind
        if "detail" in record:  # EventBridge
            dt = str(record.get("detail-type", ""))
            kind = "removed" if "Deleted" in dt or "Removed" in dt else "created" if "Created" in dt else None
            d = record["detail"]
            return d["bucket"]["name"], unquote_plus(d["object"]["key"]), kind
        return None

    def apply_event_record(self, record: dict[str, Any]) -> list[RevocationEvent]:
        """Handle one S3 notification / EventBridge dict. Ignores other buckets/prefixes and unknown kinds.

        The object's CURRENT state is re-read (HEAD), never trusted from the notification payload, so a
        delayed/reordered/duplicate event converges to the truth instead of applying stale data.
        """
        try:
            parsed = self._parse_record(record)
        except (KeyError, TypeError) as exc:
            self._record_error(f"unparseable event record: {exc!r}")
            return []
        if parsed is None:
            return []
        bucket, key, kind = parsed
        if bucket != self.bucket or not key.startswith(self.prefix) or kind is None:
            return []
        base = key.removesuffix(ACL_SUFFIX)
        remote = self._head(base)
        events = self.apply_object_change(base, remote)
        self._mark_synced()
        return events

    def _head(self, key: str) -> RemoteObject | None:
        try:
            head = self.s3.head_object(Bucket=self.bucket, Key=key)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code in ("404", "NoSuchKey", "NotFound"):
                return None
            self._record_error(f"head_object failed: {type(exc).__name__}")
            raise
        if head.get("DeleteMarker"):
            return None
        side: dict[str, Any] | None = None
        try:
            sh = self.s3.head_object(Bucket=self.bucket, Key=sidecar_key(key))
            side = {"Key": sidecar_key(key), "ETag": sh["ETag"], "VersionId": sh.get("VersionId")}
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code not in ("404", "NoSuchKey", "NotFound"):
                raise
        acl = self._acl_for(key, {sidecar_key(key): side} if side else {})
        entry = {
            "Key": key,
            "ETag": head["ETag"],
            "Size": head.get("ContentLength"),
            "VersionId": head.get("VersionId"),
        }
        return self._to_remote(entry, acl)

    def health(self) -> ConnectorHealth:
        h = super().health()
        h.coverage = {**h.coverage, "native_s3_acl_changes": False}
        h.details["digest_modes"] = sorted({str(v.get("digest_mode")) for v in self.state.values()})
        h.details["bucket"] = self.bucket
        h.details["configured_digest_mode"] = self.digest_mode
        modes = [str(v.get("digest_mode")) for v in self.state.values()]
        # Objects whose change detection rests on an ETag identity rather than a content hash.
        h.details["etag_mode_objects"] = sum(1 for m in modes if m in _ETAG_FAMILY)
        h.details["etag_opaque_encrypted_objects"] = modes.count("etag-opaque")
        if self.mode == "events":
            h.details["note"] = (
                "Event mode: apply_event_record gives near-real-time updates; keep periodic watch_once as the "
                "reconcile loop (lost notifications). freshness_sla_seconds is the reconcile interval."
            )
        return h
