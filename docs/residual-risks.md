# Residual risks

The register of what remains after the controls in `spec/SPEC.md` and `docs/threat-model.md`, and what is not proven. Each entry gives a status and the mitigation that exists today. "Open" means no mitigation exists in the repo. Nothing here has been independently reviewed; see R17.

Status values: **By design** (a stated non-guarantee), **Partial** (a mitigation exists with a known gap), **Open** (no mitigation in the repo), **Unverified** (claimed but not tested in this repo).

## Enforcement scope

**R1. Uninstrumented paths are outside the guarantee.** Direct database, cache or vector-store reads, and model calls made without the wrapper, are not checked. `benchmark/reports/latest.md` says the same. *Status: By design. Mitigation: wrap every read path (`docs/integration-guide.md`); `docs/coverage-matrix.md` lists only the adapters the conformance suite exercised. Nothing in the repo detects a bypass at runtime.*

**R2. Model-gateway coverage depends on the `untracked` mode.** `sdk-python/ales_sdk/model_gateway.py` cannot authorize items that carry no ALES id. `GuardedModelCall(untracked=...)` makes the handling explicit: `"deny"` removes them (reported in `PreparedContext.blocked_untracked`, reason `UNTRACKED_CONTEXT`); `"error"` raises `UntrackedContextError` with the item indices; `"allow"` (the default, kept for compatibility) passes them through unchecked, counts them in `DecisionSummary.untracked`, and logs a one-time warning per instance. Items whose `role` is in `exempt_roles` (default `("system",)`) are the caller's own prompt and are never offenders; exempting `"user"` would defeat the control. Under FailMode.OBSERVE nothing is blocked in any mode (counted as `observed_only`). *Status: Partial. Strict modes exist; the default remains `allow`, so protected deployments must opt in to `deny`/`error`. Untracked content inside an exempt role, or a caller that forges/omits ids on retrieved text it labels `system`, is still not covered.*

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

**R13. OIDC has no token revocation list.** `server/ales_server/oidc.py` accepts RS256 and ES256 JWTs (`exp` required) from a static JWKS (`jwks`, `jwks_file`) or a live `jwks_uri`. A `jwks_uri` is fetched over https (plain http only for 127.0.0.1/localhost), cached for `ALES_OIDC_JWKS_TTL` (300 s), refetched on an unknown `kid` at most once per `ALES_OIDC_JWKS_MIN_REFRESH` (30 s), and kept serving from cache after a failed fetch for at most `ALES_OIDC_JWKS_MAX_STALE` (3600 s) before every token is refused; with no cache a fetch failure is a 401. IdP key rotation therefore no longer needs a restart. The verifier still keeps no revocation list: a token stays valid until `exp`, and a key withdrawn at the IdP stays trusted until the cache refreshes (up to the TTL, or longer while fetches fail, up to the max-stale bound). Static bearer tokens in `ALES_TOKENS` or `ALES_TOKENS_FILE` are still loaded at process start, and rotating one requires a restart. A JWKS cache miss blocks other verifications on that replica for up to the 5 s fetch timeout. *Status: Partial (key rotation resolved; token revocation open). Mitigation: move human and service identity to OIDC so token rotation happens at the IdP; keep token lifetimes short; lower `ALES_OIDC_JWKS_TTL` if faster key withdrawal matters; stop issuance at the IdP to cut off a subject.*

**R14. Key revocation at ingress is not retroactive, as far as the repo shows.** `PATCH /v1/admin/keys/{key_id}` with `status=revoked` affects the signature check at ingress (`_enforce_signature`). This review did not find code that revokes objects already registered under that key. *Status: Unverified. Mitigation: after revoking a key, submit revocation events for the sources it issued.*

**R15. Signatures prove issuer, not truth.** A connector with a valid signing key can publish false but correctly signed envelopes. *Status: By design (SPEC signing section).*

**R16. Signatures are off by default in config.** `ALES_REQUIRE_SIGNATURES` is off when unset (`server/ales_server/config.py`). Helm sets it on. Other deployments do not. *Status: Partial. Mitigation: set it to `1` explicitly in every production environment.*

## Deployment

**R17. No third-party security review is recorded in this repo.** The repo contains internal assessment material and remediation commits (`ENGINEERING_ASSESSMENT.md`, commit `633f891`). They are not an external review. *Status: Open.*

**R18. Terraform and Helm templates are CI-validated but have not been applied to real clouds or a cluster.** The `deploy-validate` CI job runs `terraform fmt -check`, `terraform init -backend=false` and `terraform validate` on every module and `helm lint` + `helm template` on the chart with real tools; no `terraform apply` or `helm install` against a live environment has been performed. *Status: Partially verified. Mitigation: perform a real deployment in a non-production environment before relying on the templates.*

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

**R35. Separation of duties on approvals.** `POST /v1/approvals/{approval_id}/decide` returns 409 `{"detail": "separation of duties: decider matches requester"}` when the deciding subject equals either the requested principal (the `principal.id` of the `/v1/authorize` call, whose access is pending) or the requesting actor (the token subject that made the call). Both are stored on the approval (`requested_by_principal`, `requested_actor`, migration 0003) and apply to approve and deny alike. Approvals created before migration 0003 have no requester recorded and are not blocked. `ALES_APPROVAL_ALLOW_SELF=1` turns the check off (dev or single-admin deployments; the server logs a startup warning). The check compares subject strings: it cannot tell that two different subjects are the same person, and an `admin` who can mint tokens for other subjects can still collude with themselves. *Status: Resolved (enforced by default; the escape hatch is opt-in and documented in `docs/operations.md`). Mitigation: leave `ALES_APPROVAL_ALLOW_SELF` unset in production; give approvers subjects distinct from every requesting principal and service.*

**R36. Workload identity is opt-in unless `ALES_ENFORCE_WORKLOADS=strict`.** In the default `auto` mode the resolver checks `agent_id` only for tenants that have registered at least one workload, and checks workload grants (which principal may act as which agent) only for tenants that have recorded at least one grant. A tenant with no workloads is not checked at all: `agent_id` is an unverified label, and revoking a tenant's last grant switches its grant check off again. `off` disables both checks (startup warning). *Status: Partial. Mitigation: set `ALES_ENFORCE_WORKLOADS=strict` in production so an unknown agent is denied (`WORKLOAD_SUSPENDED`) even when nothing is registered; record at least one grant per agent so the grants check is active. The grants check cannot be forced on independently of grants existing.*

**R37. Caller-asserted `risk` is advisory.** `risk` on `/v1/authorize` is supplied by the caller, so a caller can lower it to avoid a policy rule keyed on `risk`. `PolicyDocument.risk_floors` (`{purpose or "*": low|medium|high}`) is the trusted control: the effective risk is the maximum of the caller's value and the floors for the request purpose and `"*"`, and a missing caller value counts as the floor. Without a floor the caller's value is used unchanged, and a rule matching `risk` exactly (for example `low`) can still be dodged by a caller who raises the risk above it. *Status: Partial. Mitigation: set floors for every purpose that must be treated as high risk; write deny rules for `high` rather than relying on `low` or `medium` to stay stable.*
