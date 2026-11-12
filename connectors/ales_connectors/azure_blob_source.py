"""Azure Blob Storage source connector (polling).

Lists blobs with ``list_blobs(name_starts_with=prefix)``; with ``versioned=True`` it lists
``include=["versions"]`` and keeps only the current version (version_id joins the version hint).

Digest modes: when the service reports ``content_settings.content_md5`` the envelope digest is sha256 of
that MD5 identity (mode ``md5``); otherwise ETag identity (mode ``etag``). Neither is a hash of the bytes
we streamed; Content-MD5 is only present if the uploader supplied or the service computed it, and an
ETag changes on every write (including metadata-only writes -> a possible spurious supersession, the
safe direction). ACLs: sidecar blob ``<name>.acl.json`` (same schema as the filesystem connector) or the
configured default classification.

Auth: ``connection_string`` or ``account_url`` + ``credential`` (or an injected ``container_client``).
Secrets are handed straight to the SDK; they are never stored on the connector, logged, or put in
``repr``/health/errors.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from typing import Any

from ales_sdk.client import InvariantClient

from .spi import (
    ACL_SUFFIX,
    DEFAULT_ACL,
    CheckpointStore,
    ConnectorHealth,
    PollingConnector,
    RemoteObject,
    parse_acl_sidecar,
    sidecar_key,
)


def _ident_digest(kind: str, value: str) -> str:
    return hashlib.sha256(f"azure-{kind}:{value}".encode()).hexdigest()


class AzureBlobConnector(PollingConnector):
    source_system = "azure_blob"
    actor = "ales-azure-blob-connector"

    def __init__(
        self,
        client: InvariantClient,
        tenant_id: str,
        container: str,
        *,
        connection_string: str | None = None,
        account_url: str | None = None,
        credential: Any | None = None,
        container_client: Any | None = None,
        prefix: str = "",
        versioned: bool = False,
        connector_id: str | None = None,
        checkpoint: CheckpointStore | None = None,
        poll_interval_seconds: float = 60.0,
        default_classification: str = "internal",
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(
            client,
            tenant_id,
            connector_id or f"azure_blob:{container}/{prefix}",
            checkpoint,
            poll_interval_seconds=poll_interval_seconds,
            clock=clock,
        )
        if container_client is None:
            from azure.storage.blob import BlobServiceClient  # deferred: optional dependency

            if connection_string:
                svc = BlobServiceClient.from_connection_string(connection_string)
            elif account_url:
                svc = BlobServiceClient(account_url=account_url, credential=credential)
            else:
                raise ValueError("provide connection_string, or account_url (+ credential), or container_client")
            container_client = svc.get_container_client(container)
        self.container = container
        self._cc = container_client
        self.prefix = prefix
        self.versioned = versioned
        self.default_acl = {**DEFAULT_ACL, "classification": default_classification}
        self._sidecar_cache: dict[str, tuple[str, dict[str, Any]]] = {}

    def __repr__(self) -> str:  # never include credentials
        return f"AzureBlobConnector(container={self.container!r}, prefix={self.prefix!r})"

    def _blobs(self) -> list[Any]:
        if self.versioned:
            blobs = self._cc.list_blobs(name_starts_with=self.prefix or None, include=["versions"])
            return [b for b in blobs if getattr(b, "is_current_version", None) or not getattr(b, "version_id", None)]
        return list(self._cc.list_blobs(name_starts_with=self.prefix or None))

    def _acl_for(self, blob: Any | None) -> dict[str, Any]:
        if blob is None:
            return dict(self.default_acl)
        etag = str(blob.etag)
        cached = self._sidecar_cache.get(blob.name)
        if cached is None or cached[0] != etag:
            body = self._cc.download_blob(blob.name).readall()
            cached = (etag, parse_acl_sidecar(body, self.default_acl))
            self._sidecar_cache[blob.name] = cached
        return dict(cached[1])

    def list_objects(self) -> list[RemoteObject]:
        blobs = self._blobs()
        sidecars = {b.name: b for b in blobs if b.name.endswith(ACL_SUFFIX)}
        out: list[RemoteObject] = []
        for b in blobs:
            if b.name.endswith(ACL_SUFFIX):
                continue
            etag = str(b.etag).strip('"')
            vid = getattr(b, "version_id", None)
            hint = etag if not vid else f"{etag}|{vid}"
            md5 = getattr(getattr(b, "content_settings", None), "content_md5", None)
            if md5:
                digest, mode = _ident_digest("md5", bytes(md5).hex()), "md5"
            else:
                digest, mode = _ident_digest("etag", etag), "etag"
            out.append(
                RemoteObject(
                    id=b.name,
                    version_hint=hint,
                    digest=digest,
                    acl=self._acl_for(sidecars.get(sidecar_key(b.name))),
                    metadata={"digest_mode": mode, "version_id": vid, "size": getattr(b, "size", None)},
                )
            )
        return out

    def health(self) -> ConnectorHealth:
        h = super().health()
        h.coverage = {**h.coverage, "native_azure_rbac_changes": False}
        h.details["digest_modes"] = sorted({str(v.get("digest_mode")) for v in self.state.values()})
        h.details["container"] = self.container
        return h
