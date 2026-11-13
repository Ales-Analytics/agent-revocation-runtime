# Product contract

What ALES INVARIANT is for, what it protects and does not, what is tested, and who must wire what. This page summarizes and links; the normative texts are [guarantees.md](guarantees.md), [threat-model.md](threat-model.md) and `spec/SPEC.md`. Every number below names its artifact.

## Primary use case

Stale or unauthorized source-derived context must not reach RAG retrieval, caches, agent memory, or downstream agents. When a source is deleted, superseded, loses an ACL, or is marked untrusted, every derivative recorded in the lineage graph (chunks, embeddings, summaries, memory entries, cached answers, handoffs, model responses) is denied at read time, then purged asynchronously.

**First customer profile.** A platform or AI-infrastructure team that runs RAG or long-lived agents on Postgres plus one vector store (Qdrant or pgvector) and optionally Redis, and that controls the retrieval path and the model call site, so it can place `authorize` in front of them.

## What ALES protects and what it cannot

| Protects | Does not (by design) |
|---|---|
| Reads through instrumented paths: guarded vector search, guarded cache get, LangGraph / LlamaIndex / ACS-v0 adapters, the Python model gateway, handoffs | Any path that does not call `authorize` (direct DB, direct cache or vector-store access, a model client without the wrapper); R1 |
| Future use of derivatives of a revoked, superseded, expired or quarantined source | Recall of content already shown to a person or sent to a model; R3 |
| Multi-parent derivatives: usable only if every parent is usable (conservative propagation, G2) | Token-level attribution: a response built from N sources records all N as parents; R4 |
| Unknown lineage: `UNKNOWN`, treated as DENY for non-public data (G3) | Prompt-injection or content maliciousness detection; trust state tracks lineage, not content; R5 |
| Tenant separation at the application layer | Storage-level tenant isolation; R31 |
| Physical removal from configured stores, with verified absence | Model weights, fine-tuning influence |
| | Truthfulness of a signed envelope (signatures prove the issuer only); R15 |

Not a compliance certification. Compliance is a property of the whole system and its operation.

## Supported and tested deployment profile

| Area | Supported | Evidence | Not covered |
|---|---|---|---|
| Control-plane database | SQLite (dev, single node); PostgreSQL 16 (production; `ALES_ENV=production` refuses SQLite) | `benchmark/reports/latest.md` (sqlite-inmem), `latest-postgres.md` (Postgres 16); `stress/` on both | Managed-DB behaviour, failover, backup drills |
| Cache | Redis (`GuardedCache`, cache purge target) | `conformance/report.md`; `docs/coverage-matrix.md` live rows when reachable | Redis Cluster / replicas |
| Vector stores | Qdrant, pgvector (native `<=>` extension), portable pgvector fallback | `docs/coverage-matrix.md`, `adapters/ales_adapters/coverage.py` | Others; the postgres benchmark's vector purge target is an in-memory stand-in |
| Frameworks | LangGraph (`guard_node`), LlamaIndex (`GuardedLlamaRetriever`), ACS v0 (`AcsContextGuard`) | `conformance/report.md` (ENFORCING, tested against fakes for the framework side) | Other frameworks; live framework runtimes |
| Source connectors | S3, Azure Blob, webhook, filesystem | `connectors/`, `adapters/ales_adapters/fs_source.py` (INGESTION_ONLY in conformance) | GCS; S3 SSE-KMS tested with moto only (R32) |
| SDKs | Python 0.2.0, TypeScript 0.2.0 | `docs/compatibility.md` | Intra-repo pairs only |
| Deploy | Docker Compose (dev only), Helm on any Kubernetes, Terraform for Azure, AWS, GCP | `.github/workflows/ci.yml` `deploy-validate`; R18 | **Template-validated only: no `terraform apply` or `helm install` against a real cloud or cluster** |
| Scale evidence | Single host, one server process (benchmark), two processes over one database (`stress/`) | R28, R29 | Multi-replica behind a load balancer, partitions, sustained load |

## Guarantees per fail mode, with exposure windows

Exposure window = longest time a revoked source can still be read through an instrumented path. Source: G4 in [guarantees.md](guarantees.md); measured parts from [residual-risks.md](residual-risks.md) R6 to R9 and `stress/test_inflight_revocation.py`.

| Mode | Window after the revocation is accepted | Defaults / measured |
|---|---|---|
| `ENFORCE`, control plane reachable | Zero for any `authorize` call that starts after acceptance (measured: zero ALLOWs, SQLite and Postgres). Plus the in-flight remainder of a call already past its lineage read, plus the SDK decision-cache TTL if that ALLOW was cached | In-flight ALLOWs arrived at most 23 ms (Postgres) / 60 ms (SQLite) late; slowest call 0.67 s under contention (R6). Cache `max_ttl` 30 s, clock-skew allowance 30 s |
| `ENFORCE`, a reader in another process that has not seen the new epoch | Until its next server contact or the cache TTL | 30 s; server in-flight part measured, cross-replica SDK propagation is bounded by TTL and not measured (R7) |
| `BOUNDED_OFFLINE`, control plane unreachable | Lease + time before the revocation reached the control plane + in-flight window. After lease expiry protected reads are denied | `ALES_SNAPSHOT_LEASE` default 60 s; SDK `offline_lease_seconds` 60 s (R8); `service_outage` benchmark scenario counts the lease window as "bounded exposure", not an escape |
| `WARN` | Unbounded by the runtime (an operator may override a denial) | Not a protection mode |
| `OBSERVE` | Unbounded; decisions logged and labelled incomplete | Not a protection mode |
| Future-dated revocation (`effective_at`) | Reads before `effective_at` are legitimate; cutover is enforced by `valid_until` in the response | A reader that cached an ALLOW before the event was accepted serves it until TTL (R6) |

Measured outcome in both benchmark profiles (git revision `1f0a228`): 0 escapes in 387 post-revocation read attempts across 13 scenarios, 0 false blocks in 293 legitimate reads. These are sequential single-client runs on one machine.

## What "purged" means per store

Read-denial never waits for purge (G1). Purge is asynchronous, at-least-once, and verified:

| Store | Delete | Verified-absence re-check (version-aware) |
|---|---|---|
| Redis cache | idempotent delete of the data key and reverse index | key and reverse index are gone |
| Qdrant | delete the point | point is gone |
| pgvector | delete the row (atomic, version-aware `DELETE`) | row is gone |
| Stores with no configured target | Nothing. Rows of that kind stay `pending` in `GET /v1/outbox/stats` | n/a |

Rules: a newer version under the same `context_id` is neither deleted nor treated as a failure; if the object is still present after the delete the handler raises and the outbox retries; six failed attempts become a dead letter that an admin lists and requeues (R11). Verification is a read-after-delete on the same store, so an eventually consistent replica can still pass it (R12). With `ALES_PURGE_TARGETS` unset the handler is log-only and marks rows done without purging (R10); check that `GET /v1/outbox/stats` `worker.handlers` shows `purge:...`. Measured purge time (stand-in stores, harness-driven, excluding the worker poll interval): 200 ms p50 in-process, 904 ms p50 postgres profile (3 samples each; `benchmark/reports/`).

## Responsibility split

| ALES provides | The integrator must wire |
|---|---|
| Control plane, graph, deterministic decisions, revocation engine, outbox, signed snapshots, audit chain | **Purge targets:** `ALES_PURGE_TARGETS` for every store holding derivatives (R10), and alerting on `dead` outbox rows (R11) |
| Guarded adapters and a model gateway with `untracked="protected"` default | **Freshness guard in retrieval:** call `freshness_guard` / `assert_fresh` in every retrieval path; nothing calls it for you (R33) |
| `DecisionSummary.coverage` per model call | **Model-gateway coverage:** route every model call through it; choose `untracked` and `exempt_roles` deliberately (R2) |
| Audit chain, `GET /v1/audit/head`, optional `ALES_AUDIT_EXPORT_FILE` | **Audit-export anchoring destination:** poll the head or ship the export to storage the database operator cannot rewrite (R23) |
| Static-token and OIDC verification; hot-reloaded token file and denylist | **OIDC / token config:** issuers, audiences, short token lifetimes, stopping issuance at the IdP (no token revocation list, R13) |
| Workload and grant gates (`strict` in production) | **Workload registration:** register every agent and its grants; risk floors for purposes that must be high risk (R36, R37) |
| Restore-check script (`scripts/ales_restore_check.py`) | Scheduling the revocation export and running `verify` / `reapply` after any restore, then re-purging (R22) |
| Compose, Helm and Terraform templates | A real non-production apply before relying on them (R18); TLS, DNS, backups, dashboards (`deploy/README.md`) |

Roll-out path: [rollout.md](rollout.md). Public risk register: [residual-risks.md](residual-risks.md).
