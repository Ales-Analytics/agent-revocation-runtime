# Four HTTP calls against a disposable tenant

Captured in order from the FastAPI server on in-memory SQLite. Each request uses `Content-Type: application/json` and `Authorization: Bearer <tenant token>`. The headings identify the service role. To replay, bind the credential to the handbook tenant, use fresh IDs and the current event time, and keep parent IDs and versions consistent across calls.

## POST /v1/sources (ingest)

Register the source digest and authority. The application retains the handbook text.

Request

```json
{
  "context_id": "ffb90617-9a7f-4c97-8856-ab7121f6a30d",
  "tenant_id": "handbook",
  "object_id": "return-policy",
  "object_version": "1",
  "content_digest": "sha256:6315667c9e20f11334de9461f742fd9e22d81b70dfefe2c78a83051707d8920d",
  "kind": "source",
  "source_system": "support",
  "source_acl_ref": null,
  "classification": "internal",
  "trust_state": "verified",
  "parent_refs": [],
  "policy_version": "v1",
  "valid_from": "2026-11-23T17:41:02.479382Z",
  "expires_at": null,
  "principal_scope": [
    "reader"
  ]
}
```

HTTP 200

```json
{
  "context_id": "ffb90617-9a7f-4c97-8856-ab7121f6a30d",
  "object_version": "1",
  "tenant_id": "handbook"
}
```

## POST /v1/derivations (ingest)

Register a chunk with the exact source version as its parent.

Request

```json
{
  "context_id": "7bc7dca6-9d5b-4555-b6d3-48e4f5ae6c1d",
  "tenant_id": "handbook",
  "object_id": "return-policy#1",
  "object_version": "1",
  "content_digest": "sha256:ffd7280513ce285e6d9dc8d0b7078c4f39c8fe0e69b0d0a87d8af2965e445d7a",
  "kind": "chunk",
  "source_system": "ales-sdk",
  "classification": "internal",
  "trust_state": "verified",
  "parent_refs": [
    {
      "context_id": "ffb90617-9a7f-4c97-8856-ab7121f6a30d",
      "object_version": "1"
    }
  ],
  "policy_version": "v1",
  "valid_from": "2026-11-23T17:41:02.479419Z",
  "principal_scope": [
    "reader"
  ]
}
```

HTTP 200

```json
{
  "context_id": "7bc7dca6-9d5b-4555-b6d3-48e4f5ae6c1d",
  "object_version": "1",
  "tenant_id": "handbook"
}
```

## POST /v1/revocations (revoke)

Revoke the source and advance the tenant epoch.

Request

```json
{
  "event_id": "52036a23-c625-4e4d-996a-afd563aeb475",
  "tenant_id": "handbook",
  "source_id": "ffb90617-9a7f-4c97-8856-ab7121f6a30d",
  "reason": "deleted",
  "effective_at": "2026-11-23T17:41:02.479435Z"
}
```

HTTP 200

```json
{
  "event_id": "52036a23-c625-4e4d-996a-afd563aeb475",
  "revocation_epoch": 1
}
```

## POST /v1/releases (read)

The gate evaluates a send to the support inbox. The receipt denies the action, so the host must withhold the chunk.

Request

```json
{
  "principal": {
    "type": "user",
    "id": "reader"
  },
  "purpose": "support",
  "action": "send",
  "destination": "support-inbox",
  "objects": [
    {
      "context_id": "7bc7dca6-9d5b-4555-b6d3-48e4f5ae6c1d",
      "version": "1"
    }
  ]
}
```

HTTP 200

```json
{
  "receipt_id": "0703ad65-72a4-49b6-a022-6a83e6e71600",
  "decision": "DENY",
  "reason": [
    "RELEASE_DENIED",
    "ANCESTOR_DELETED"
  ],
  "valid_until": "2026-11-23T17:41:02.833463Z",
  "revocation_epoch": 1,
  "policy_version": "p0"
}
```
