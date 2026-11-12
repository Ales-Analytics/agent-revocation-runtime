# ALES INVARIANT — Specification v0.2

> Context must never outlive its authority.

This directory is the **public contract** of the runtime. Code conforms to spec, never the reverse. Schema changes require a version bump and a migration note.

## The invariant

`usable(object, principal, purpose, time) = true` **only if** every required ancestor source is current, intact, not revoked, and authorized for that principal and purpose at that time.

When lineage is incomplete the decision is **UNKNOWN**, and UNKNOWN is treated as **DENY** for protected (non-`public`) context. The runtime never guesses that an object is safe merely because it exists in a store.

## Objects and kinds

Every tracked object has a `context_id` (UUID), a `tenant_id`, an `object_version`, a `content_digest` (sha256), and a `kind`:
`source | chunk | embedding | summary | memory | cache | artifact`.

Non-source objects MUST carry `parent_refs` — the full set of `(context_id, object_version)` pairs that produced them. When exact attribution is unknowable (e.g. a model response built from N prompt sources), **all N are parents**. The spec forbids claiming finer-grained neural attribution.

## Authority propagation (conservative by construction)

A derivative's effective authority is computed from its parents:

| Field | Rule |
|---|---|
| classification | most restrictive of parents (`public < internal < confidential < restricted`) |
| principal_scope | set intersection of parents' scopes |
| purpose_scope | set intersection of parents' scopes |
| expires_at | earliest non-null parent expiry |
| trust_state | least trusted (`verified < untrusted < quarantined`) |

Multi-parent rule: a derivative is usable only if **every** parent is usable for the current principal and purpose. Declassification/widening is only possible via an explicit, authorized, audited reclassification operation — never implicit.

## Decisions

`/v1/authorize` returns exactly one of:

| Decision | Meaning |
|---|---|
| ALLOW | All ancestors current, intact, authorized. |
| DENY | At least one ancestor revoked/unauthorized/expired, or UNKNOWN on protected data. |
| UNKNOWN | Lineage incomplete or authority unresolvable. Callers MUST treat as DENY for protected context. |
| REFRESH | A parent was superseded; a re-derivation path exists. |
| REDACT | Usable only after removing fields tied to a revoked parent (deterministic transforms only). |
| QUARANTINE | An ancestor is marked compromised/poisoned. |
| HUMAN_REVIEW | Policy requires operator approval. |

Every decision carries: `reason` codes (array), `revocation_epoch`, `policy_version`, `trace_id`, and per-object verdicts.

### Reason codes (v0.1)
`ANCESTOR_ACL_REVOKED`, `ANCESTOR_DELETED`, `ANCESTOR_SUPERSEDED`, `ANCESTOR_EXPIRED`, `ANCESTOR_QUARANTINED`, `PRINCIPAL_NOT_IN_SCOPE`, `PURPOSE_NOT_IN_SCOPE`, `LINEAGE_INCOMPLETE`, `OBJECT_UNKNOWN`, `TENANT_MISMATCH`, `POLICY_SNAPSHOT_STALE`, `OK`.

## Revocation semantics

A `RevocationEvent` (see schema) is durable before it is acted on. Accepting an event:
1. writes a tombstone for the source version (or all versions if `source_version` is null),
2. marks all known descendants unusable (graph traversal),
3. increments the tenant's `revocation_epoch`,
4. emits invalidation events to adapters (async purge; retried).

**Synchronous deny precedes asynchronous cleanup.** A descendant whose purge failed is still denied at use time because its lineage references a revoked ancestor.

## Fail modes

`OBSERVE` (log only, labelled incomplete), `WARN` (operator override required), `ENFORCE` (block DENY/UNKNOWN; production default), `BOUNDED_OFFLINE` (signed policy snapshot valid within a configured lease; protected reads denied after lease expiry). The system publishes its maximum exposure window; it never claims instantaneous revocation.

## Authentication and tenant binding (v0.2)

Every API call carries a bearer service token. The server maps the token to a `(tenant_id, roles)` record in its token registry; the request's effective tenant is **always** the token's tenant. A body or header tenant that disagrees with the token's tenant is rejected with 403 — caller-supplied tenant IDs are never trusted. Roles: `ingest` (register sources/derivations), `revoke` (submit revocations), `read` (authorize/lineage/verify), `admin` (key and token management). Unauthenticated requests are rejected 401 on every endpoint except `/v1/healthz` and `/v1/readyz`.

## Scoped and delayed revocation (v0.2)

- `effective_at` is enforced: an accepted event whose `effective_at` is in the future is durable immediately but denies reads only once `now >= effective_at`. Epoch advances at acceptance; the decision carries the pending state.
- `affected_scope` is enforced: when present, descendants are denied only for principals/purposes matching the scope; other principals keep access. A scoped tombstone never widens access and full (unscoped) revocation always wins over a scoped one.
- Events are idempotent by `event_id`; duplicate and reordered deliveries must converge to the same final state. An event for an unknown source is durable, bumps the epoch, and applies retroactively if the source is registered later with a matching version.

## Invalidation outbox and purge (v0.2)

Each revocation writes one outbox row per affected object. A dispatcher leases rows (single-flight via lease token + expiry), invokes the registered purge handler per store, marks success, and retries failures with exponential backoff up to a dead-letter state that is visible via connector health. Purge is at-least-once and idempotent; a crash between tombstone and purge must never re-expose data, because use-time decisions depend only on the tombstone.

## Signed policy snapshots and offline operation (v0.2)

`GET /v1/snapshot` (read role) returns a signed snapshot: `{tenant_id, revocation_epoch: integer, policy_version, issued_at (RFC3339 with timezone), lease_seconds: integer, signature, key_id?}`. The signature is Ed25519 over the RFC 8785 canonical JSON of the payload minus `signature` and `key_id`, base64-encoded (standard or url-safe). `GET /v1/snapshot/public_key` (read role — never anonymous, to avoid a circular trust bootstrap) returns `{key_id, public_key_b64, ephemeral}`. A server enforcing signatures refuses to start without a persistent snapshot key unless explicitly overridden, because an ephemeral per-process key breaks verification across replicas and restarts. BOUNDED_OFFLINE clients may serve cached ALLOW decisions only while holding a verified, unexpired snapshot whose epoch matches the decision's epoch; otherwise protected reads are denied. The SDK decision cache key includes `(tenant_id, principal_type, principal_id, purpose, context_id, object_version, policy_version)`.

Authorize responses carry an optional `valid_until` (top-level and per object): the earliest still-pending revocation `effective_at` in the requested objects' lineage that matches the request's principal and purpose. A client MUST NOT serve a cached ALLOW at or past its `valid_until`, and SHOULD stop serving it a clock-skew margin (default 30 s) early; an ALLOW already inside that margin is not cached. Reason-code mapping from revocation reasons: `deleted → ANCESTOR_DELETED`, `acl_changed → ANCESTOR_ACL_REVOKED`, `version_superseded → ANCESTOR_SUPERSEDED` (or decision `REFRESH` when a live newer version exists), `expired → ANCESTOR_EXPIRED`, `compromised`/`poisoned` → decision `QUARANTINE` with `ANCESTOR_QUARANTINED`.

## Audit ledger (v0.2)

Every decision, registration, revocation and admin action appends a record `{seq, prev_hash, hash, at, tenant, actor (authenticated principal), action, detail}` where `hash = sha256(prev_hash || canonical(record))`. The chain is verifiable end-to-end; records are never updated or deleted. Document content never enters the ledger.

## Signing

Envelopes and revocation events are signed with Ed25519: a detached signature over **RFC 8785 (JCS)** canonical JSON of the object minus the `signature` and `issuer_key_id` fields. `issuer_key_id` names a key in the tenant's trusted-issuer registry (`key_id`, `tenant_id`, `public_key`, `status: active|retired|revoked`). When the server runs with `require_signatures` enabled (production default), an envelope or event with a missing signature, an unknown/retired/revoked key, or a failed verification is rejected at ingress — helper round-trip tests are not ingress security. Keys live in a KMS/vault; configs carry key *references* only. The signature proves integrity and issuer identity — not content truthfulness.

## Non-guarantees (normative)

The runtime cannot: recall information already seen by a person or model, erase model weights, govern uninstrumented paths, or certify regulatory compliance. Adapters that observe but cannot block MUST be labelled `OBSERVE_ONLY` and are excluded from coverage claims.
