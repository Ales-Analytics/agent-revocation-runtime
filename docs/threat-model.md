# Threat model

Scope: the ALES INVARIANT runtime as specified in `spec/SPEC.md`. The runtime answers one question at each instrumented boundary: is this derivative usable by this principal, for this purpose, right now? This document lists the threats it addresses, the control for each, and the limits that remain. The limits are as important as the controls.

## Assets

- Source objects (documents, records) with a classification, principal scope, purpose scope, expiry and trust state.
- Derivatives of those sources: chunks, embeddings, summaries, agent memories, caches, artifacts and agent handoffs.
- The derivation graph (`parent_refs`), revocation events and signed policy snapshots.

## Threats

| # | Threat | Control | Residual limit |
|---|---|---|---|
| 1 | **Permission revoked after ingestion.** A source's ACL is removed, but chunks, embeddings, summaries and memories built from it still exist. | Graph-based descendant invalidation. An accepted revocation writes a tombstone, traverses the derivation graph, marks all known descendants unusable, and increments the tenant `revocation_epoch`. Authorize-before-use at each read path returns `DENY` with `ANCESTOR_ACL_REVOKED` even if physical purge has not run. | Only descendants recorded in the graph are covered. A derivative created by an uninstrumented path has no recorded parent and cannot be denied. Content already shown to a person or sent to a model is not recalled. |
| 2 | **Stale source version.** A source is re-issued (v2) but derivatives of v1 remain in use. | Version digests (`object_version`, `content_digest`) in every envelope. A superseded parent yields `REFRESH` (re-derivation path) or `DENY` with `ANCESTOR_SUPERSEDED`. | Supersession is only detected when the new version is registered with the runtime. A source changed outside the registered path looks unchanged until its digest is recomputed. |
| 3 | **Memory or context poisoning.** Untrusted or attacker-controlled content enters an agent's memory or retrieval context and is later treated as trusted. | Quarantine propagation. A source marked compromised or untrusted moves its descendants to `quarantined` (least-trusted state wins across multi-parent derivation). Decisions return `QUARANTINE` with `ANCESTOR_QUARANTINED`. | The runtime tracks trust state; it does not judge whether content is malicious. Poisoning that enters through a source the runtime was told is `verified` is not detected. Prompt injection inside an allowed context is outside the runtime's control. |
| 4 | **Cross-tenant leakage.** An object from tenant A is returned to tenant B through shared caches, a shared graph or a shared index. | Tenant-partitioned graph. Every object carries `tenant_id`; graph traversal, revocation epochs and lookups are scoped to the tenant. Cross-tenant references return `TENANT_MISMATCH`. | Isolation depends on adapters passing the correct `tenant_id` and on the store enforcing the partition. An adapter that omits or spoofs the tenant on its own read path bypasses the check. Storage-level isolation (separate databases, row-level security) is a deployment decision and is not implied by the runtime. |
| 5 | **Compromised connector.** A source connector or adapter registers false envelopes (wrong ACLs, forged lineage, suppressed revocations). | Signed events. Envelopes and revocation events are Ed25519-signed over RFC 8785 canonical JSON, and ingress rejects unknown, retired or revoked issuer keys when signatures are required. The repo has no connector heartbeat or automatic unhealthy-marking: connector health is visible only through invalidation outbox state (`GET /v1/outbox/stats`, dead-letter count). A silent connector does not by itself turn decisions into `UNKNOWN`/`DENY`. | A valid signature proves the issuer, not the truth of the content. A connector holding a valid signing key can publish false but correctly signed envelopes. Key compromise must be handled through KMS/vault rotation, which the runtime does not perform itself. |
| 6 | **Tampered metadata.** Envelope fields (classification, scopes, expiry, parent refs) are changed in storage or in transit. | Signed envelopes. Each envelope carries a detached signature over canonical JSON minus the `signature` field; verification fails on any change. Authority propagation is recomputed deterministically from parents (most restrictive wins). | Tampering with the runtime's own database by a principal with write access, before signing, or with the signing key, is not detected by signatures alone. Protect the store and the key path; audit logs are only as strong as their storage. |
| 7 | **Revocation-service outage.** The control plane is unreachable, so clients cannot learn of revocations. | Bounded-offline lease and fail-closed. Clients hold a signed policy snapshot valid for a configured lease. In `BOUNDED_OFFLINE` mode, protected reads are denied once the lease expires. Unknown lineage is `DENY` for protected data. | During the lease a client may allow reads that a revocation would have denied. The maximum exposure window equals the configured lease plus any delay before the revocation is accepted. Deployments must publish their configured window. Non-protected (`public`) data is not fail-closed by design. |

## Assumptions

- The enforcement point (SDK wrapper, adapter or middleware) is on the path to the model, cache or index it protects. See `docs/integration-guide.md`.
- Signing keys are held in a KMS or vault. Configuration carries key references only.
- Clocks used for `expires_at` and lease checks are trustworthy within the deployment.
- The derivation graph is written by the runtime or its adapters. Lineage supplied by an untrusted caller is only as good as that caller.

## Out of scope

- Model weight contents, and information a person or model has already read or retained.
- Attacks on the hosting platform, operating system or network below the runtime.
- Denial of service against the control plane beyond the fail-mode behaviour above.
- Legal or regulatory compliance. The runtime is not a compliance certification. See `docs/guarantees.md`.
