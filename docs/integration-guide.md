# Integration guide

This guide describes how to write an adapter that brings a context source, store, cache, memory or agent framework under Agent Revocation Runtime control. It assumes familiarity with `spec/SPEC.md`.

An adapter is only as strong as its coverage. Before writing code, answer the four questions below and record the answers in `docs/coverage-matrix.md`.

## The four questions

1. **Where does context enter?** Identify every point where content from a source (document store, connector, user upload, tool result) becomes available to your system. Each entry point must register the source with an envelope.
2. **Where are derivatives created?** Identify every transformation that produces a new object from one or more inputs: chunking, embedding, summarization, memory writes, cache writes, model responses, handoffs to other agents. Each must record its `parent_refs`.
3. **Where does retrieval or handoff happen?** Identify every read path: vector search, cache get, memory recall, prompt assembly, agent-to-agent transfer. Each must call authorize before returning content.
4. **Where can it block?** Identify where your system can actually refuse to use content: before a prompt is sent, before a cache hit is returned, before a handoff is delivered. If there is no such point, the adapter is `OBSERVE_ONLY`.

If you cannot answer question 4 for a path, that path is not covered.

## Envelope registration at ingestion

Every tracked object needs an envelope with `context_id`, `tenant_id`, `object_version`, `content_digest` (sha256), `kind`, classification, principal and purpose scopes, expiry and trust state. Non-source kinds must include `parent_refs` listing every `(context_id, object_version)` that produced them.

Rules:

- Register sources before any derivative that references them. The runtime rejects derivatives whose parents are unknown with `LINEAGE_INCOMPLETE`.
- When attribution is uncertain, list all candidate parents. Do not guess a subset.
- Sign envelopes with the key reference from configuration. Never place key material in adapter configuration.
- Send the content digest of what you actually stored, not of what you intended to store.

## Authorize before use

At every retrieval, memory-recall, cache-read and handoff boundary, call the authorize API with the object, principal, purpose and the current time, then act on the decision:

| Decision | Adapter behaviour |
|---|---|
| `ALLOW` | Return the content. |
| `DENY` | Do not return it. Return nothing or a neutral refusal. Record the reason codes. |
| `UNKNOWN` | Treat as `DENY` for any non-`public` data. |
| `REFRESH` | Do not return the stale object. Trigger the re-derivation path if one exists. |
| `REDACT` | Return only the transformed output the runtime supplies. Do not reassemble the redacted fields yourself. |
| `QUARANTINE` | Do not return it. Do not write it back into memory or cache. |
| `HUMAN_REVIEW` | Hold the request until an operator decides. |

Do not cache an authorization result beyond its `revocation_epoch`.

## Session taint on revocation

When a revocation affects a conversation or agent session that has already used a revoked derivative, the session is tainted. Subsequent turns in that session must re-authorize every context item they use. Adapters must propagate the taint to any handoff or memory write produced by that session, because those are new derivatives of the tainted content.

## Fail modes

Each adapter runs in one of four modes. The mode is set in configuration, and the deployment publishes the exposure window for it (see `docs/guarantees.md`).

- **OBSERVE.** Decisions are computed and logged, but content is not blocked. Labelled incomplete. Counts as `OBSERVE_ONLY` for coverage purposes.
- **WARN.** Denials are shown to an operator, who can override them. Not a protection guarantee for coverage.
- **ENFORCE.** `DENY`, `UNKNOWN` (for protected data), `QUARANTINE` and `REFRESH` block use. This is the production default.
- **BOUNDED_OFFLINE.** Uses a signed policy snapshot valid for a configured lease. Protected reads are denied after the lease expires. The adapter must refuse to start in this mode without a valid snapshot.

An adapter must not silently fall back from ENFORCE to OBSERVE or WARN. Any mode change is an operator action and must be logged.

## OBSERVE_ONLY labelling rule

If the adapter cannot block at any of its read paths, it must:

1. declare itself `OBSERVE_ONLY` in its manifest and in its documentation;
2. run in OBSERVE mode, or in a mode the operator has explicitly chosen to label as such;
3. be excluded from every coverage claim, including counts in the coverage matrix;
4. not be described in release notes as enforcing revocation.

An adapter that blocks some paths and observes others must list each path with its mode. Coverage is claimed only for the enforcing paths.

## Checklist

- [ ] The four questions are answered and recorded in `docs/coverage-matrix.md`.
- [ ] Every entry point registers envelopes with digests and scopes.
- [ ] Every derivation records all parents.
- [ ] Every read path calls authorize and handles all seven decisions.
- [ ] Sessions taint on revocation and re-authorize.
- [ ] The fail mode is configured and matches the published exposure window.
- [ ] `OBSERVE_ONLY` is declared if any path cannot block.
- [ ] The adapter passes the conformance suite in `conformance/`, or ships as `OBSERVE_ONLY`.

## The integration contract

**ContextReference.** Every piece of context an adapter touches carries a reference to its registered envelope: `tenant_id`, `context_id`, `object_version`, `content_digest`, and optionally `authority_ref` and `source_connector`. It is defined once in `ales_adapters.carrier` (`ContextReference.to_metadata()` / `from_metadata()`); the metadata keys are `ales_context_id`, `ales_version`, `ales_tenant`, `ales_digest`, `ales_authority_ref`, `ales_connector`. `from_metadata` returns `None` when no identity key is present and raises `CarrierError` on a partial or corrupt stamp (an id without a version, a non-string value). Legacy stamps (id + version only) still parse, with empty tenant/digest. Vector payloads and cache records keep their existing `context_id`/`version` pair (`to_payload()`); LangGraph node updates keep `ales_context_id`/`ales_object_version` (`to_state_update()`).

**Stamping rule.** Every adapter preserves the reference across retrieval results, framework messages, memory, caches, model inputs and outputs, tool I/O, handoffs and artifacts, and builds new stamps only through the carrier helpers. Content without a reference is untracked and must be treated per the fail mode, never assumed safe.

**Capability manifests.** `ales_adapters.manifest_report()` states, per adapter, what it actually mediates: `source_ingestion`, `parent_preservation` (with the transforms), `retrieval_interception`, `memory_interception`, `model_context_interception`, `tool_egress_interception`, `physical_purge`, `session_reset`, `tested_upstream_versions` and `enforcement_level`. Each value is `supported`, `partial: <scope>`, `unsupported` or `n/a`. This replaces "works with framework X": a claim is a row, and an unlisted capability is not covered. `conformance/report.md` ties every `retrieval_interception: supported` claim to a passing contract run; claims without one render `UNVERIFIED`.

**Diagnostics.**

- `ales doctor [--server URL]`: package versions against manifest ranges, config file, `/v1/healthz`, `/v1/readyz`, snapshot public key (needs a token); PASS/WARN/FAIL, exit 1 on FAIL. Server-side checks are `python -m ales_server.preflight`.
- `ales integrations inspect`: the manifest table.
- `ales coverage report [--json]`: manifests merged with the verification states from `conformance/report.md`.
