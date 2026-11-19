"""The ContextReference carrier: the one place the ALES stamp format is defined.

Every adapter that moves context (retrieval results, framework messages, memory, caches, model inputs and
outputs, tool I/O, handoffs, artifacts) preserves this reference alongside the content, so the gateway can
authorize it later. Three serialisations exist, all produced here:

* ``to_metadata()``: the canonical ``ales_*`` keys used on framework nodes/messages (``ales_context_id``,
  ``ales_version``, ``ales_tenant``, ``ales_digest``, ``ales_authority_ref``, ``ales_connector``);
* ``to_payload()``: the bare ``context_id`` / ``version`` pair stored inside vector-store payloads and cache
  records (a pre-existing wire format, unchanged);
* ``to_state_update()``: the ``ales_context_id`` / ``ales_object_version`` pair LangGraph nodes return in
  their state update (a pre-existing wire format, unchanged).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ales_sdk.errors import AlesError

META_CONTEXT_ID = "ales_context_id"
META_VERSION = "ales_version"
META_TENANT = "ales_tenant"
META_DIGEST = "ales_digest"
META_AUTHORITY_REF = "ales_authority_ref"
META_CONNECTOR = "ales_connector"
META_KEYS = (META_CONTEXT_ID, META_VERSION, META_TENANT, META_DIGEST, META_AUTHORITY_REF, META_CONNECTOR)

STATE_CONTEXT_ID = "ales_context_id"
STATE_VERSION = "ales_object_version"


class CarrierError(AlesError):
    """A partial or corrupt ALES stamp (an id without a version, non-string values, ...)."""


@dataclass(frozen=True)
class ContextReference:
    """Pointer to a registered envelope. Legacy stamps (id + version only) carry empty tenant/digest."""

    tenant_id: str
    context_id: str
    object_version: str
    content_digest: str
    authority_ref: str | None = None
    source_connector: str | None = None

    def __post_init__(self) -> None:
        for name in ("tenant_id", "context_id", "object_version", "content_digest"):
            if not isinstance(getattr(self, name), str):
                raise CarrierError(f"{name} must be a string")
        if not self.context_id or not self.object_version:
            raise CarrierError("context_id and object_version are required")
        for name in ("authority_ref", "source_connector"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise CarrierError(f"{name} must be a string or None")

    @classmethod
    def from_envelope(cls, env: Mapping[str, Any]) -> ContextReference:
        return cls(
            tenant_id=str(env.get("tenant_id", "")),
            context_id=str(env["context_id"]),
            object_version=str(env["object_version"]),
            content_digest=str(env.get("content_digest", "")),
            authority_ref=env.get("authority_ref"),
            source_connector=env.get("source_connector"),
        )

    def to_metadata(self) -> dict[str, str]:
        metadata = {
            META_CONTEXT_ID: self.context_id,
            META_VERSION: self.object_version,
            META_TENANT: self.tenant_id,
            META_DIGEST: self.content_digest,
        }
        if self.authority_ref is not None:
            metadata[META_AUTHORITY_REF] = self.authority_ref
        if self.source_connector is not None:
            metadata[META_CONNECTOR] = self.source_connector
        return metadata

    def to_payload(self) -> dict[str, str]:
        """Vector payload / cache record form (``context_id`` + ``version``)."""
        return {"context_id": self.context_id, "version": self.object_version}

    def to_state_update(self) -> dict[str, str]:
        """LangGraph node-update form (``ales_context_id`` + ``ales_object_version``)."""
        return {STATE_CONTEXT_ID: self.context_id, STATE_VERSION: self.object_version}

    @classmethod
    def from_metadata(cls, d: Mapping[str, Any] | None) -> ContextReference | None:
        """``None`` when no ALES identity key is present; ``CarrierError`` on a partial or corrupt stamp."""
        if not isinstance(d, Mapping):
            return None
        context_id, version, tenant_id = d.get(META_CONTEXT_ID), d.get(META_VERSION), d.get(META_TENANT)
        if context_id is None and version is None and tenant_id is None:
            return None
        if context_id is None or version is None:
            raise CarrierError(
                f"partial ALES stamp: {META_CONTEXT_ID} and {META_VERSION} must both be present"
            )
        for key in META_KEYS:
            value = d.get(key)
            if value is not None and not isinstance(value, str):
                raise CarrierError(f"corrupt ALES stamp: {key} must be a string, got {type(value).__name__}")
        return cls(
            tenant_id=d.get(META_TENANT) or "",
            context_id=context_id,
            object_version=version,
            content_digest=d.get(META_DIGEST) or "",
            authority_ref=d.get(META_AUTHORITY_REF),
            source_connector=d.get(META_CONNECTOR),
        )

    @classmethod
    def from_payload(cls, record: Mapping[str, Any]) -> ContextReference | None:
        context_id, version = record.get("context_id"), record.get("version")
        if context_id is None and version is None:
            return None
        if context_id is None or version is None:
            raise CarrierError("partial payload stamp: context_id and version must both be present")
        return cls("", str(context_id), str(version), "")


def stamp_node_metadata(node: Any, ref: ContextReference) -> None:
    """Write the carrier into ``node.metadata`` and keep it out of embeddings / LLM prompts."""
    node.metadata.update(ref.to_metadata())
    for attribute in ("excluded_embed_metadata_keys", "excluded_llm_metadata_keys"):
        keys = getattr(node, attribute, None)
        if isinstance(keys, list):
            for metadata_key in META_KEYS:
                if metadata_key not in keys:
                    keys.append(metadata_key)


def payload_with_reference(
    base: Mapping[str, Any] | None, ref: ContextReference, **extra: Any
) -> dict[str, Any]:
    """Vector payload: caller payload, then ``extra`` fields, then the reference (reference keys win)."""
    return {**(base or {}), **extra, **ref.to_payload()}
