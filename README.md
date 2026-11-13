# ALES INVARIANT

**Context must never outlive its authority.**

An AI application ingests a document while access is permitted, chunks it, embeds it, summarizes it into agent memory, caches an answer. Later the document is deleted, superseded, or the user loses access. The source system knows. The vector store, the cache, the agent's memory, and the second agent downstream **do not** — and a fresh query happily serves the stale derivative.

ALES INVARIANT is a vendor-neutral **context integrity and revocation runtime**: it tracks the source dependencies of AI context across every derivative, and blocks, refreshes, redacts or quarantines derived context the moment its source authority is no longer valid.

```
usable(object, principal, purpose, time) = true
  only if every required ancestor source is current, intact,
  not revoked, and authorized for that principal and purpose at that time.
```

Incomplete lineage ⇒ UNKNOWN ⇒ treated as DENY for protected data. Decisions are deterministic — **no LLM is ever the access authority**.

## See the failure (and the fix) in two minutes

```bash
git clone <repo> && cd ales-invariant
python examples/revoke-rag-source/demo.py
```

No API key, no Docker, no model. A restricted HR document is indexed, chunked, summarized into agent memory and cached; its ACL is then narrowed. Every derivative — retrieval, cache replay, memory read — is denied with `ANCESTOR_ACL_REVOKED` **before any physical purge runs**. 11/11 checkpoints, exit 0.

For the full stack: `docker compose -f deploy/docker-compose.yml up -d` then `python examples/revoke-rag-source/demo.py --server http://localhost:8787`.

## Proof, not promises: RevocationBench

Security infrastructure should ship with its own falsifier. `python -m revocationbench` replays 8 scenario families — ACL revocation, source deletion, version supersession, poisoned source, cache replay, agent handoff, multi-tenant collision, control-plane outage — and measures what actually escapes.

Latest checked-in results (run at revision `959172b` using the in-process SQLite harness; see `benchmark/reports/latest.md` for caveats):

| Metric | Result |
|---|---|
| Stale-context escape rate | **0 / 85 post-revocation reads** |
| False-block rate | 0 / 159 legitimate reads |
| Lineage completeness | 100% (94 derivatives) |
| Decision overhead | p50 5.74 ms / p95 8.67 ms / p99 110.60 ms |
| Revocation→deny latency | p50 5.90 ms / p95 21.02 ms |

What is **not** covered is listed in the report and in [docs/guarantees.md](docs/guarantees.md): uninstrumented paths, physical purge timing, cross-process decision-cache TTL staleness, real network/Postgres latency. We publish exposure windows; we do not claim instantaneous revocation, recall of already-seen information, or compliance certification.

## How it works

- **Context envelope** (`spec/`) — signed, versioned authority metadata for every source and derivative (never the content itself).
- **Derivation graph** (`core/`) — parent→child lineage; a model output built from N sources records all N as parents (no fake neural attribution).
- **Conservative propagation** — a derivative inherits the most restrictive classification, intersected scopes, earliest expiry, least trust. It can never widen by accident.
- **Revocation engine** — durable event → tombstone all descendants → epoch bump → async purge. Synchronous deny always precedes cleanup.
- **Use-time enforcement** (`sdk-python/`, `adapters/`) — authorize immediately before context enters a model, memory, cache or handoff. Fail modes: OBSERVE / WARN / ENFORCE / BOUNDED_OFFLINE. Adapters that cannot block are labelled OBSERVE_ONLY and excluded from coverage claims.

It integrates **beside** your stack — frameworks, vector stores, caches, clouds — and replaces none of it.

## Repository

| Dir | Contents |
|---|---|
| `spec/` | The public contract: JSON Schemas + SPEC.md (start here) |
| `core/` | Graph, deterministic resolver, revocation engine |
| `server/` | FastAPI control plane for sources, derivations, revocations, authorization, policy, workloads, approvals, OIDC and metrics |
| `sdk-python/` | Python client, decision cache, session taint, fail modes, handoff and model gateway, `ales` CLI |
| `sdk-typescript/` | TypeScript client, decision cache, signed snapshots and fail modes |
| `adapters/` | Filesystem sources, guarded vector stores and caches, purge handlers, LangGraph, LlamaIndex and ACS integrations |
| `connectors/` | Source integrations, including S3 and Azure Blob Storage |
| `benchmark/` | RevocationBench scenarios, runner, reports |
| `stress/` | Load and concurrency scenarios for service deployments |
| `conformance/` | Adapter contract tests (ENFORCING / INGESTION_ONLY / NON_ENFORCING) |
| `docs/` | Threat model, guarantees, operations, upgrades and residual risks |
| `deploy/` | Docker Compose, Helm chart and Terraform modules for cloud deployments |

Dev: `pip install -e ".[dev]"` then `pytest -q`. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

Status: pre-release. The protocol spec is v0.3; package metadata still reports v0.1.0. Apache-2.0. ALES INVARIANT is a working codename.
