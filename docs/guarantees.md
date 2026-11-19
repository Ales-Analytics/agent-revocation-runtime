# Guarantees and limits

This document states the guarantees the runtime makes, the fail-mode exposure windows it publishes, and the things it cannot do. Where the spec and this document differ, `spec/SPEC.md` governs.

## Guarantees

**G1. Revocation is enforced at read time before purge completes.** After a revocation event is accepted (durably recorded), every instrumented read path denies descendants of the revoked source. This holds even if asynchronous purge from caches, indexes or memory stores has not finished. The check uses the derivation graph and the tenant `revocation_epoch`, not the state of the purge.

**G2. Propagation is conservative.** A derivative is never more permissive than its parents:
- classification is the most restrictive of its parents;
- principal and purpose scopes are the intersection of parents' scopes;
- expiry is the earliest non-null parent expiry;
- trust state is the least trusted of its parents.

A multi-parent derivative is usable only if every parent is usable for the current principal and purpose. Widening requires an explicit, authorized, audited reclassification.

**G3. UNKNOWN is DENY for protected data.** If lineage is incomplete or authority cannot be resolved, the decision is `UNKNOWN`, and callers must treat it as `DENY` for any classification above `public`. The runtime never treats an object as safe because it exists in a store.

**G4. Published maximum exposure window per fail mode.** Each deployment publishes, for each fail mode it runs, the longest interval during which a revoked source can still be read through an instrumented path. The window is computed from the configured settings (for example, the bounded-offline lease and the revocation acceptance path), not measured as a constant. The runtime never claims instantaneous revocation.

| Fail mode | Exposure window |
|---|---|
| `ENFORCE` | Time from revocation acceptance to the next authorization call on each instrumented path. Under ENFORCE, a revocation the runtime has accepted is visible to every instrumented path that queries it. |
| `BOUNDED_OFFLINE` | Up to the configured lease, plus the time before the revocation reached the control plane. Protected reads are denied after lease expiry. |
| `WARN` | Not a protection guarantee. Denials are reported but can be overridden by an operator, so exposure is unbounded by the runtime. |
| `OBSERVE` | No enforcement. Exposure is unbounded by the runtime. Decisions are logged and labelled incomplete. |

## Non-guarantees

The following capabilities are outside the runtime's scope.

- **It cannot recall information already seen.** If a person has read a document, or a model has received it in a prompt, revocation does not remove that knowledge or that output. It only stops future derivative use through governed paths.
- **It cannot erase model weights.** If content was used in training or fine-tuning, the runtime has no mechanism to remove its influence from the model.
- **It cannot govern uninstrumented or bypass paths.** Any read path that does not call authorize (direct database queries, direct cache access, a model client called without the wrapper) is outside the guarantee. Coverage is only as complete as the instrumented paths. See `docs/coverage-matrix.md`.
- **It cannot give exact neural attribution.** When a model response is built from N prompt sources, the runtime records all N as parents. It does not and cannot tell which source influenced which token. Over-attribution is the designed behaviour; under-attribution is a bug.
- **It is not a compliance certification.** Using the runtime does not make a system compliant with any law, regulation, contract or standard. Compliance is a property of the whole system and its operation, and it requires assessment by the people responsible for that system.
- **It does not verify content truthfulness.** Signatures prove who issued an envelope, not that its content is accurate.

## OBSERVE_ONLY adapters

An adapter that can observe context but cannot block its use is labelled `OBSERVE_ONLY`. Such adapters:

- emit lineage and decision records;
- are excluded from every coverage claim, including counts in `docs/coverage-matrix.md`;
- must not be described as enforcing revocation in any release note, README or marketing material.

A labelled adapter is still useful for discovery and audit. It is not a control.
