# Residual risks

The register of what remains after the controls in `spec/SPEC.md` and `docs/threat-model.md`, and what is not proven. Each entry gives a status and the mitigation that exists today. "Open" means no mitigation exists in the repo. Nothing here has been independently reviewed; see R17.

Status values: **By design** (a stated non-guarantee), **Partial** (a mitigation exists with a known gap), **Open** (no mitigation in the repo), **Unverified** (claimed but not tested in this repo).

## Enforcement scope

**R1. Uninstrumented paths are outside the guarantee.** Direct database, cache or vector-store reads, and model calls made without the wrapper, are not checked. `benchmark/reports/latest.md` says the same. *Status: By design. Mitigation: wrap every read path (`docs/integration-guide.md`); `docs/coverage-matrix.md` lists only the adapters the conformance suite exercised. Nothing in the repo detects a bypass at runtime.*

**R2. Model-gateway coverage is a count, not a block.** `sdk-python/ales_sdk/model_gateway.py` passes items that carry no ALES id through unchecked. They are counted in `DecisionSummary.untracked`, and `coverage = tracked / total`. *Status: Partial. Mitigation: monitor `coverage`; treat any untracked item as uncovered. The gateway does not refuse them.*

**R3. Information already disclosed cannot be recalled.** Content already read by a person or sent to a model is not removed by revocation. *Status: By design (SPEC non-guarantee). Mitigation: classification, short expiry and narrow scopes limit what is disclosed in the first place.*

**R4. No neural attribution.** A model response built from N prompt sources records all N as parents. Over-attribution is intended; the system cannot say which source influenced which token. *Status: By design.*

**R5. Prompt injection inside an allowed context is not detected.** Trust state tracks lineage, not content. *Status: By design (threat model row 3).*

## Staleness and timing

**R6. A disconnected reader can serve a cached ALLOW up to the cache TTL after a revocation.** The SDK decision cache defaults to `max_ttl` 30 s and clock skew 30 s. The benchmark notes that a reader which cached an ALLOW before a future-dated event was accepted, and never contacts the server again, serves that entry until TTL. Responses without `valid_until` (v0.2 servers) give no earlier cutover. *Status: Partial. Mitigation: TTL and `valid_until` (v0.3). Bounded by TTL, not by revocation.*

**R7. Cross-process decision-cache staleness is bounded by TTL, not measured.** A reader in another process that did not see the new epoch may serve a cached ALLOW until its next server contact or the TTL. The RevocationBench readers share the revoking client, so this window is not exercised. *Status: Unverified. Mitigation: TTL of 30 s. Add a multi-process test before making any multi-replica exposure claim.*

**R8. Exposure in BOUNDED_OFFLINE equals the lease plus acceptance delay.** Default `ALES_SNAPSHOT_LEASE` is 60 s, and the SDK `offline_lease_seconds` default is 60 s. The window is published, not zero. *Status: By design (guarantees G4). Mitigation: set the lease deliberately and publish it.*

**R9. Clock skew.** Clients with badly skewed wall clocks are protected only up to the 30 s skew allowance. *Status: Partial.*

## Purge and cleanup

**R10. Purge handlers are log-only by default, and the shipped app uses the default.** `server/ales_server/main.py` ends with `app = create_app()`. The default handler logs that a purge is due, purges nothing, and marks the row `done`. Use-time denial still holds, because it depends on tombstones, not purge. Physical cleanup in caches, indexes and memory does not happen. *Status: Open in the shipped configuration. Mitigation: a custom entrypoint that passes `outbox_handlers=` built from `ales_adapters.purge.PurgeRegistry`. Check `GET /v1/outbox/stats` `worker.handlers` shows `purge:...`, not `log_only`.*

**R11. Dead letters have no recovery API.** Rows that exhaust six attempts stay `dead`. The server offers no endpoint to list or requeue them. *Status: Open. Mitigation: `dead` count in `/v1/outbox/stats`; a runbook for direct database recovery is still needed.*

**R12. Purge timing is measured only against in-process stand-ins.** The purge latency in the benchmark excludes the worker's poll interval, real store latency and retries. *Status: Partial.*

## Identity and ingress

**R13. OIDC verifies against a static JWKS only.** `server/ales_server/oidc.py` accepts RS256 and ES256 JWTs (`exp` required) from keys loaded once from `ALES_OIDC_CONFIG`. There is no `jwks_uri` fetch, so IdP key rotation needs a restart, and the verifier has no token revocation list: a token stays valid until `exp`. Static bearer tokens in `ALES_TOKENS` or `ALES_TOKENS_FILE` are still loaded at process start, and rotating one requires a restart. *Status: Partial. Mitigation: move human and service identity to OIDC so token rotation happens at the IdP; restart replicas when the JWKS changes; keep token lifetimes short; stop issuance at the IdP to cut off a subject.*

**R14. Key revocation at ingress is not retroactive, as far as the repo shows.** `PATCH /v1/admin/keys/{key_id}` with `status=revoked` affects the signature check at ingress (`_enforce_signature`). This review did not find code that revokes objects already registered under that key. *Status: Unverified. Mitigation: after revoking a key, submit revocation events for the sources it issued.*

**R15. Signatures prove issuer, not truth.** A connector with a valid signing key can publish false but correctly signed envelopes. *Status: By design (SPEC signing section).*

**R16. Signatures are off by default in config.** `ALES_REQUIRE_SIGNATURES` is off when unset (`server/ales_server/config.py`). Helm sets it on. Other deployments do not. *Status: Partial. Mitigation: set it to `1` explicitly in every production environment.*

## Deployment

**R17. No third-party security review is recorded in this repo.** The repo contains internal assessment material and remediation commits (`ENGINEERING_ASSESSMENT.md`, commit `633f891`). They are not an external review. *Status: Open.*

**R18. Terraform and Helm have not been run against real clouds or a cluster.** `deploy/README.md` says neither tool was available in the authoring environment. *Status: Unverified. Mitigation: run `terraform fmt -check && terraform validate`, `helm lint` and `helm template` in CI, then a real deployment in a non-production environment.*

**R19. Migration race on concurrent startup.** `run_migrations` has no lock in the repo. Concurrent replicas against a database behind head can race. The Helm hook Job avoids this for Helm releases only. *Status: Partial. Mitigation: hook Job, or one replica first. `ALES_SKIP_STARTUP_MIGRATIONS` exists in code (see R20).*

**R20. Documentation said `ALES_SKIP_STARTUP_MIGRATIONS` did not exist.** `server/ales_server/main.py` reads it. `deploy/README.md` and `deploy/helm/ales-invariant/templates/NOTES.txt` now describe it. *Status: Resolved (documentation corrected). The chart still does not set it; `docs/operations.md` sections 1 and 3 document the switch.*

**R21. Rolling upgrade readiness is untested.** `/v1/readyz` requires the database revision to equal the running image's head. Old pods become NotReady once migration `0002` runs. *Status: Unverified. Mitigation: `docs/upgrades.md`; test in staging.*

**R22. Restore can resurrect revoked sources.** A point-in-time restore to before a revocation removes the tombstone and epoch. *Status: Open. Mitigation: re-apply revocations after any restore from a log kept outside the database. No tooling exists for this.*

**R23. Audit tail truncation is not detectable from the chain.** `ales_core.audit.head` returns the newest `(seq, hash)`, but no HTTP route exposes it. External anchoring is an operator task. `GET /v1/audit/verify` writes an audit record on each call. *Status: Partial. Mitigation: periodic export of head to WORM storage; alert on anchor gaps.*

**R24. Docs said the container runs as root.** `deploy/Dockerfile` sets `USER 10001:10001` and installs runtime dependencies only. The deploy docs are corrected. *Status: Resolved (documentation corrected). Confirm the container user on the image you deploy.*

**R25. Insecure defaults if env is misconfigured.** An unset `DATABASE_URL` uses a SQLite file in the working directory. An unset `ALES_SNAPSHOT_KEY` with signatures off uses an ephemeral key. `ALES_DEV_ALLOW_ANONYMOUS=1` with no tokens grants all roles. *Status: Partial. The server fails closed for missing tokens (503) and for signatures-on without a key, but not for the other two.*

**R26. Ephemeral snapshot key override.** `ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY=1` lets a signing-enforced server start with a per-process key. *Status: By design (explicit override). Mitigation: do not set it outside dev.*

**R27. Metrics are per process; the public scrape shows cross-tenant sums.** `GET /v1/metrics` (read role) renders Prometheus text. Counters are per process and reset on restart, so the scraper must sum across replicas. `ALES_METRICS_PUBLIC=1` exempts the path from auth and then renders totals over all tenants. The Helm ServiceMonitor is disabled and sends no bearer token. *Status: Partial (resolved with caveats). Mitigation: scrape each replica with a read token and aggregate with `sum()`; keep `ALES_METRICS_PUBLIC` off; restrict network access to the endpoint (`docs/operations.md` section 6).*

## Evidence limits

**R28. Benchmark and conformance evidence is from a single machine and an earlier revision.** RevocationBench ran at git revision `633f891`, in-process through the FastAPI TestClient with in-memory SQLite, with 6-object lineages. Latencies exclude network, TLS, Postgres and multi-replica effects. The working tree has uncommitted v0.3 changes not covered by that run. *Status: Open. Mitigation: rerun at release revision against Postgres and multi-replica.*

**R29. Concurrency and scale are not characterised.** Revocation racing an in-flight read is not tested; scenarios are sequential. Traversal cost on deep or wide graphs is not measured. *Status: Open.*

**R30. Lineage completeness depends on callers.** Derivatives created through uninstrumented paths have no parent and cannot be denied. Lineage supplied by an untrusted caller is only as good as that caller. *Status: By design (threat model assumptions).*

**R31. Storage-level tenant isolation is not provided.** Tenancy is enforced in the application (`bind_tenant`, graph scoping). Database-level isolation (separate databases, row-level security) is a deployment decision. *Status: By design (threat model row 4).*

**R32. S3 connector digests are ETag identities, not content hashes.** Envelope `content_digest` for objects not streamed is `sha256("s3-etag:" + etag)` (`connectors/ales_connectors/s3_source.py`). Multipart uploads with different part sizes give a different ETag, which yields a spurious supersession (the safe direction). SSE-KMS and SSE-C ETags are not content hashes, so a content change that does not change the ETag may go undetected. *Status: Partial. Mitigation: verify the bucket's encryption configuration; use the hashed path where needed.*

**R33. Connector freshness has no SLA or heartbeat.** No health marking exists for connectors. A silent connector does not turn decisions into DENY. *Status: Open. Mitigation: operator-defined freshness monitoring, derived from the lease and TTL values.*

**R34. Tokens are digests in memory, plaintext in the file.** The registry stores SHA-256 digests after load, but `ALES_TOKENS_FILE` and the Kubernetes secret hold plaintext tokens. *Status: By design for in-memory. Protect the file and secret as credentials.*

**R35. No separation of duties on approvals.** `POST /v1/approvals/{approval_id}/decide` requires only the `admin` role and records the deciding subject. Nothing compares that subject with the caller whose `/v1/authorize` created the `approval.request`. A subject holding both `read` (needed to trigger a request) and `admin` can request an approval and approve it. The 30-day cap on `ttl_seconds` limits how long a decision holds, not who may make it. *Status: Open. Mitigation: give `admin` only to subjects that do not also hold `read`; review `approval.decide` records against the `approval.request` actor for the same `approval_id`.*
