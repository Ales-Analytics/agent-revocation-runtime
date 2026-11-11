# ALES INVARIANT — Specification v0.1

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

## Signing

Envelopes and revocation events are signed with Ed25519 (detached signature over RFC 8785 JCS canonical JSON of the object minus the `signature` field). Keys live in a KMS/vault; configs carry key *references* only. The signature proves envelope integrity and issuer identity — not content truthfulness.

## Non-guarantees (normative)

The runtime cannot: recall information already seen by a person or model, erase model weights, govern uninstrumented paths, or certify regulatory compliance. Adapters that observe but cannot block MUST be labelled `OBSERVE_ONLY` and are excluded from coverage claims.
