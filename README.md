# ALES INVARIANT

**Context must never outlive its authority.**

A vendor-neutral context integrity and revocation runtime for AI systems. It tracks the source dependencies of AI context (chunks, embeddings, summaries, agent memories, caches, handoffs) and blocks, refreshes, redacts or quarantines derived context whenever its source authority is no longer valid — the source was deleted, superseded, de-permissioned, expired or compromised.

```
usable(object, principal, purpose, time) = true
  only if every required ancestor source is current, intact,
  not revoked, and authorized for that principal and purpose at that time.
```

Incomplete lineage ⇒ UNKNOWN ⇒ DENY for protected data. No LLM ever makes the access decision.

- `spec/` — the public contract: envelope, revocation event and decision API schemas (start here)
- `core/` — derivation graph, deterministic authority resolver, revocation engine
- `server/` — FastAPI control plane
- `sdk-python/` — client, enforcement wrappers, CLI
- `benchmark/` — RevocationBench: reproducible stale-context escape measurement
- `docs/` — threat model, guarantees **and non-guarantees**

Status: pre-release, under active development. Apache-2.0.
