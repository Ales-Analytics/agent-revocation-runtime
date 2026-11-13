# Changelog

All notable changes are recorded here, in the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. Versioning and compatibility rules, including what a minor release may change, are in [docs/compatibility.md](docs/compatibility.md). The project is pre-release; before 1.0 the stability rules are a goal, not a guarantee.

## [0.3.0] - Unreleased

Server 0.3.0, spec v0.3 (schema `$id` `/spec/v0.3/`), Alembic head `0003`, Python and TypeScript SDK 0.2.0.

### Added

- **Kernel.** Derivation graph with conservative propagation, deterministic resolver (UNKNOWN is DENY for protected data), revocation engine (durable event, descendant tombstones, tenant epoch bump), invalidation outbox with leased dispatch, retries and dead letters, tamper-evident audit chain.
- **Authorization boundary.** `/v1/authorize` with `valid_until` cutover, delayed (`effective_at`) and scoped revocation, signed policy snapshots with a bounded-offline lease, Ed25519-signed ingress (`ALES_REQUIRE_SIGNATURES`), request body limit, production-mode startup guard (`ALES_ENV=production` refuses unsafe settings), credential denylist, hot-reloaded token file.
- **Policy and identity.** Policy documents with `risk_floors`, workload registry, grants (`ALES_ENFORCE_WORKLOADS`, `ALES_REQUIRE_GRANTS`), delegations, approvals with separation of duties (migrations `0002`, `0003`), OIDC JWT verification with static JWKS or a live `jwks_uri` (cache TTL, unknown-`kid` refetch, bounded stale window), Prometheus metrics at `/v1/metrics`.
- **SDKs.** Python client with epoch-bound decision cache, session taint, fail modes (OBSERVE, WARN, ENFORCE, BOUNDED_OFFLINE), handoff, model gateway (`untracked` modes, `DecisionSummary.coverage`) and the `ales` CLI; TypeScript client with decision cache, signed snapshots and fail modes.
- **Adapters and connectors.** Guarded vector store (Qdrant, native pgvector, portable pgvector fallback), guarded Redis cache, LangGraph, LlamaIndex and ACS v0 adapters, per-adapter coverage declarations, verified purge handlers (`ALES_PURGE_TARGETS`: Redis, Qdrant, pgvector); filesystem, S3 (ETag or content digests), Azure Blob and webhook source connectors with a freshness registry.
- **Operations and deploy.** Docker Compose (dev), Helm chart (sets `ALES_ENV` from `config.env`, default `production`; migration hook Job), Terraform modules for Azure, AWS and GCP, outbox dead-letter list and requeue endpoints, audit head endpoint and optional append-only export, `scripts/ales_restore_check.py` (export, verify, reapply), supply-chain CI workflow (dependency audit, SBOM, secret scan), runbooks in `docs/`.
- **Evidence.** RevocationBench with 13 scenarios and two profiles, `inprocess` and `postgres` (each report header records its source revision; 0 escapes in 387 post-revocation reads in both profiles); adapter conformance suite and generated report; `stress/` concurrency suite (revoke-versus-read races, in-flight bound, multi-process, concurrent registration, epoch monotonicity, outbox contention, adversarial tenants; SQLite and Postgres).
- **Documentation.** Product contract ([docs/product.md](docs/product.md)), rollout path ([docs/rollout.md](docs/rollout.md)), guarantees, threat model, residual-risk register, operations, upgrades, compatibility, security policy.

### Known limits

Listed in full in [docs/residual-risks.md](docs/residual-risks.md). Notably: Terraform and Helm templates are validated by tooling but never applied to a real cloud or cluster; no independent security review; multi-replica, partition and sustained-load behaviour is unmeasured; per-token OIDC revocation via the denylist (jwt_subs, jwt_jtis, require_jti); revocation cannot recall content already disclosed.
