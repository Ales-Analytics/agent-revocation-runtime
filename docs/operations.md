# Operations

Operator guide for running the ALES INVARIANT control plane (server 0.3.0). Everything here is taken from the code in this repo. Where the code and the deploy docs disagree, the code is the authority. Known gaps are in `docs/residual-risks.md`.

## 1. Required environment

Read by `server/ales_server/config.py`, `main.py`, `auth.py` and `snapshot.py`. Unset values fall back to the defaults shown.

| Variable | Default if unset | Production setting | Notes |
|---|---|---|---|
| `DATABASE_URL` | `sqlite:///./invariant.db` | `postgresql+psycopg://...?sslmode=require` | **If unset the server silently uses a SQLite file in the working directory.** Always set it. |
| `ALES_TOKENS` | none | JSON object, or use the file form | `{token: {tenant_id, roles, subject}}`. Roles: `ingest`, `revoke`, `read`, `admin`. Tokens are stored as SHA-256 digests in memory. |
| `ALES_TOKENS_FILE` | none | path to the JSON above (Helm/Terraform mount it) | Same token must not appear in both sources. **Hot-reloaded**: the file is stat-ed at request time, at most once per 5 s, and re-read when its mtime or size changes, so rotating tokens needs no restart (section 7b). A reload that fails validation is logged and the previous registry stays in force. |
| `ALES_DEV_ALLOW_ANONYMOUS` | off | never set (not even to `0`) | Dev only. Every caller gets all roles and chooses its tenant. Ignored when tokens are configured. With `ALES_ENV=production` any value is a startup refusal. |
| `ALES_REQUIRE_SIGNATURES` | **off** (`config.py` default) | `1` | Helm defaults it to `1`. With it off, unsigned envelopes and revocations are accepted. |
| `ALES_SNAPSHOT_KEY` | none (ephemeral key generated) | base64 raw 32-byte Ed25519 seed, identical on every replica | Required when signatures are on, see section 2. |
| `ALES_SNAPSHOT_KEY_ID` | derived from public key | optional | |
| `ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY` | off | leave off | Overrides the startup refusal below. Each process then signs with its own key. |
| `ALES_SNAPSHOT_LEASE` | `60` (seconds, integer >= 1) | set deliberately | Lease written into every snapshot. This is the server-side input to the bounded-offline exposure window. |
| `ALES_MAX_BODY` | `1048576` bytes | as needed | Body cap, enforced before authentication. |
| `ALES_OUTBOX_INTERVAL` | `5.0` seconds | as needed | `0` disables the background outbox worker. |
| `ALES_SKIP_STARTUP_MIGRATIONS` | off | `1` on pods that run behind a migration job, see section 3 | Read by `main.py`. The Helm chart does not set it. |
| `ALES_OIDC_CONFIG` | off | JSON, see section 2b | Enables OIDC JWT verification alongside the static tokens. Optional `"require_jti": true` rejects (401) tokens without a `jti` claim so every token can be revoked individually via the denylist. |
| `ALES_ENFORCE_WORKLOADS` | `auto` | `strict` | `auto`: workload checks apply only to tenants that registered a workload. `strict`: every request with an `agent_id` is checked, so an unknown agent is denied (`WORKLOAD_SUSPENDED`) even when the tenant has no workloads. `off`: no workload or grant checks, loud startup warning. Anything else is a startup error. See section 12. |
| `ALES_APPROVAL_ALLOW_SELF` | off | leave off | `1` lets the requester decide their own approval. Dev or single-admin only, startup warning. See section 12. |
| `ALES_OIDC_JWKS_TTL` | `300` s (>= 1) | as needed | Cache lifetime of a fetched `jwks_uri` key set. See section 2b. |
| `ALES_OIDC_JWKS_MIN_REFRESH` | `30` s (>= 0) | as needed | Minimum gap between JWKS fetch attempts, including unknown-`kid` refetches. |
| `ALES_OIDC_JWKS_MAX_STALE` | `3600` s (>= 0) | as needed | Longest the cached key set is served after fetches start failing. After that every OIDC token is refused. |
| `ALES_ENV` | `development` | `production` | `production` makes `create_app()` refuse to start (one `ConfigError` listing every violation) when: no tokens and no OIDC; `ALES_DEV_ALLOW_ANONYMOUS` is set at all; signatures are off (unless `ALES_ALLOW_UNSIGNED_INGRESS=1`); no persistent `ALES_SNAPSHOT_KEY` (unless `ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY=1`; required regardless of the signature setting); `DATABASE_URL` is SQLite (unless `ALES_ALLOW_SQLITE=1`); `ALES_ENFORCE_WORKLOADS` resolves to `off`. It also defaults `ALES_ENFORCE_WORKLOADS` to `strict`. `deploy/Dockerfile` sets it; the compose stack sets `development`. In development, startup logs one `ALES DEVELOPMENT MODE` warning listing every unsafe setting in effect. The Helm chart does not set it. Any other value is a startup error. |
| `ALES_ALLOW_UNSIGNED_INGRESS` | off | leave off | Production only: explicit override that lets signatures stay off. Logged as a warning at every start. |
| `ALES_ALLOW_SQLITE` | off | leave off | Production only: explicit override that lets a single-node SQLite database run. Logged as a warning at every start. |
| `ALES_DENYLIST_FILE` | none | path to a JSON denylist | `{"subjects": [...], "jwt_subs": [...], "jwt_jtis": [...], "key_ids": [...]}`. Hot-reloaded (stat at most once per 5 s). Listed identities get 401; `jwt_jtis` revokes individual OIDC tokens by their `jti` claim. Malformed at startup is a startup error; malformed on reload keeps the last good content. See section 7b. |
| `ALES_AUDIT_EXPORT_FILE` | none | path on separate, append-only storage | Every committed audit record is also written as one JSON line. Failures are logged and counted, never fail the request. See section 7. |
| `ALES_PURGE_TARGETS` | none (log-only purge in development) | JSON list of target objects | Real purge handlers (redis cache, Qdrant, pgvector) with post-purge verification. A bad value is a startup error. In production, unset is a startup violation unless `ALES_PURGE_POLICY=deny-only`. See section 4. |
| `ALES_PURGE_POLICY` | `purge` | `purge` or `deny-only` | Production only enforces it: `purge` with no `ALES_PURGE_TARGETS` is a startup violation (revoked bytes would never be erased). `deny-only` starts with one prominent warning (use-time denial only; revoked bytes remain in stores until purged externally) and `/v1/outbox/stats` reports `worker.handlers: "deny_only"`. `deny-only` together with `ALES_PURGE_TARGETS` is contradictory and refused. Development: unchanged log-only default. Check the whole environment with `python -m ales_server.preflight` (PASS/WARN/FAIL table, `--json`, exit 1 on FAIL) before deploying. |
| `ALES_REQUIRE_GRANTS` | off (on when `ALES_ENV=production`) | `1` / `0` | Pins the grants gate: when the workload gate applies to a request with an `agent_id`, the principal must hold a grant for that agent even if the tenant has no grant rows (deleting the last grant cannot reopen the gate). Set `0` explicitly to opt out in production. See section 12. |
| `ALES_METRICS_PUBLIC` | off | leave off | `1` exempts `GET /v1/metrics` from auth and makes it render cross-tenant sums. See section 6. |

Malformed values (non-numeric, bad booleans, bad JSON, bad base64 keys, duplicate tokens, unknown roles, tenant ids ending in `:verify`) are startup errors. No tokens configured means protected routes return 503.

Helm, `deploy/helm/ales-invariant/templates/configmap.yaml`, sets `ALES_ENV` (from `config.env`, default `production`), `ALES_REQUIRE_SIGNATURES`, `ALES_OUTBOX_INTERVAL`, `ALES_SNAPSHOT_LEASE`, `ALES_MAX_BODY`, `ALES_SNAPSHOT_KEY_ID` (optional) and `ALES_TOKENS_FILE`. `DATABASE_URL` and `ALES_SNAPSHOT_KEY` come from the referenced Secret.

Production checklist:

- `ALES_ENV=production` (the Dockerfile sets it; with it, the server refuses to start on any of the unsafe settings below instead of warning).
- `DATABASE_URL` set to Postgres with TLS.
- `ALES_REQUIRE_SIGNATURES=1`.
- `ALES_SNAPSHOT_KEY` set to the same persistent key on every replica.
- Tokens in a file or secret store, least-privilege roles per consumer (ingest, revoke, read, admin).
- `ALES_DEV_ALLOW_ANONYMOUS` unset.
- Outbox handlers wired to real purge stores (section 4).
- The image runs non-root. `deploy/Dockerfile` sets `USER 10001:10001` and installs runtime dependencies only. Confirm the container user on the image you deploy.

## 2. Snapshot signing key

With `ALES_REQUIRE_SIGNATURES` on, `create_app()` raises `ConfigError` at startup if `ALES_SNAPSHOT_KEY` is missing, unless `ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY=1`. With signatures off, a missing key yields an ephemeral key with a warning.

An ephemeral key changes on every restart and differs between replicas. Clients that verify snapshots then cannot verify snapshots from a different replica or from before a restart.

Verify after deploy: `GET /v1/snapshot/public_key` returns `{key_id, public_key_b64, ephemeral}`. `ephemeral` must be `false`, and the key must match the one you generated.

Rotating the key invalidates outstanding snapshots. Publish the new public key to clients first (`deploy/README.md`, rotation rule 5). The repo has no mechanism that serves two keys at once.

## 2b. OIDC JWT authentication (optional)

Enabled by `ALES_OIDC_CONFIG`, a JSON object read by `server/ales_server/oidc.py`:

```json
{"issuer": "https://idp.example.com/", "audience": "ales-invariant",
 "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
 "claim_mapping": {"tenant_id": "org_id", "subject": "sub", "roles": "ales_roles"}}
```

- Exactly one of `jwks` (inline `{"keys": [...]}`), `jwks_file` (read once at startup) or `jwks_uri`. Inline and file keys are static: rotation needs a restart.
- `jwks_uri` is fetched lazily with httpx (5 s timeout, TLS verification on, no redirects, 1 MiB cap). It must be `https`; plain `http` is accepted only for `127.0.0.1` and `localhost`. Anything else is a startup error. Fetched keys obey the same rules as static ones (RS256 >= 2048 bits or ES256, kid rules).
  - The key set is cached for `ALES_OIDC_JWKS_TTL` seconds. A token with an unknown `kid` triggers a refetch, at most once per `ALES_OIDC_JWKS_MIN_REFRESH` seconds, so rotation works without a restart and junk `kid` values cannot hammer the IdP.
  - Fail closed: if the fetch fails and nothing is cached, every JWT is a 401 (retries are throttled by the same minimum gap). If it fails with a cache, the cached keys keep serving, with one warning logged per failure streak, but only until `ALES_OIDC_JWKS_MAX_STALE` seconds after the streak began; after that every JWT is a 401 until a fetch succeeds (one error is logged).
  - A cache miss holds a lock for up to the fetch timeout, so other JWT verifications on that replica wait. Each replica fetches on its own.
- Algorithms: `RS256` (RSA >= 2048 bits) and `ES256` (P-256) only. `none`, `HS*` and `crit` headers are rejected.
- `iss` must equal `issuer` exactly, `aud` must contain `audience`, and `exp` is required. Clock skew allowance is 60 s.
- `claim_mapping.roles` is a claim name, or `{"static": ["read"]}` to give every token from that issuer fixed roles. Identity comes only from mapped claims; a missing or malformed one is a 401. Roles must be known roles (`ingest`, `revoke`, `read`, `admin`).
- When OIDC is on, a bearer token shaped like a JWT is verified as OIDC and is never looked up in `ALES_TOKENS`. Every failure is a 401. Other tokens go to the static registry, if one is configured.
- Per-subject and per-token revocation go through the denylist (`ALES_DENYLIST_FILE`, section 7b): list the mapped subject in `jwt_subs`, or the token's `jti` in `jwt_jtis`. Set `"require_jti": true` so every token carries one. A token with no denylist entry stays valid until its `exp`. Stopping issuance at the IdP and waiting out the token lifetime is the fallback. Denylist changes apply within about 5 s on each replica that re-reads the file (R13).
- Malformed config (bad JSON, missing issuer or audience, zero or several of `jwks`/`jwks_file`/`jwks_uri`, unknown static roles) is a startup error.

## 3. Database and migrations

Schema is managed only by Alembic (`core/alembic/`, programmatic helpers in `core/ales_core/migrations.py`):

- `0001` initial schema: audit_log, invalidation_outbox, issuer_keys, revocation_events, tenants, tombstones, context_objects, derivation_edges.
- `0002` policy_documents, workloads, workload_grants, delegations, approvals (SPEC v0.3).
- `0003` approvals: `requested_by_principal` and `requested_actor` columns (separation of duties). Nullable, so existing rows survive; downgrade drops them.
- `head_revision()` is the newest script in the image. `current_revision(engine)` is what the database is at. `run_migrations(engine, revision="head")` upgrades. `downgrade_migrations(engine, revision="base")` downgrades. See `docs/upgrades.md` before using downgrade.

**Startup migrations.** `create_app()` runs `run_migrations(engine)` on every process start unless `ALES_SKIP_STARTUP_MIGRATIONS=1` is set. Set it only on pods whose schema is migrated first by something else. `/v1/readyz` still reports `migrations: behind` until the schema reaches head.

**Helm.** `templates/migration-job.yaml` is a `pre-install,pre-upgrade` hook Job (weight -5) that runs `run_migrations` once before the Deployment rolls. Its settings are `migrations.enabled` (default true), `backoffLimit: 2` and `activeDeadlineSeconds: 600`. If the Job fails, the release fails. Logs: `kubectl logs job/<release>-migrate`.

**Race.** `run_migrations` has no advisory lock or other cross-process guard in the repo. When several replicas start against a database that is behind head, their Alembic runs can race. The hook Job avoids this for Helm releases. Outside Helm, either run migrations once out of band before starting replicas, or start one replica first and then scale. Do not start a fresh database with several replicas at once.

**Readiness depends on revision.** `/v1/readyz` returns `migrations: behind` unless the database revision equals the image's head. Expect any pod whose image head differs from the database revision to report NotReady. See `docs/upgrades.md`.

**Startup on Helm.** Pods run `run_migrations` at start unless `ALES_SKIP_STARTUP_MIGRATIONS=1` is set. The chart does not set it and has no values flag for it, so pods run the migration as a no-op at head. Adding such a flag would be a template change.

**Postgres driver.** The Helm migration Job calls `create_engine(DATABASE_URL)` directly. The app uses `pool_pre_ping=True` on non-SQLite URLs. Use `postgresql+psycopg://`.

## 4. Outbox worker and purge handlers

The background worker (`server/ales_server/worker.py`) runs when `ALES_OUTBOX_INTERVAL > 0` and the database is not in-memory SQLite. Each tick calls `OutboxDispatcher.run_once()`, then waits the interval. Rows are leased (60 s lease), retried with backoff (1, 5, 30, 120, 600 s), and dead-lettered after 6 failed attempts (`core/ales_core/outbox.py`).

**Purge targets (`ALES_PURGE_TARGETS`).** The shipped app builds real purge handlers from this JSON list; without it the handler is log-only (rows go `done`, nothing is purged). Under `ALES_ENV=production` a missing `ALES_PURGE_TARGETS` is a startup violation unless you choose `ALES_PURGE_POLICY=deny-only` explicitly (use-time denial only, one startup warning, `worker.handlers` reports `deny_only`). Example:

```json
[
  {"kind": "cache", "type": "redis",  "url": "redis://redis:6379/0", "prefix": ""},
  {"kind": "chunk", "type": "qdrant", "url": "http://qdrant:6333", "collection": "ales_vectors", "api_key_env": "QDRANT_API_KEY"},
  {"kind": ["chunk", "embedding"], "type": "pgvector", "url": "postgresql+psycopg://u:p@db/vec", "table": "ales_vectors_native", "dim": 1536}
]
```

- `kind` is an outbox `store_kind` (`chunk`, `embedding`, `summary`, `memory`, `cache`, `artifact`), a list of them, or `"*"`. Rows of a kind with no target stay `pending`.
- `redis` uses the reverse index written by `GuardedCache` (`prefix` must match the cache's). `qdrant` needs `collection` (`api_key_env` names an env var, so the key is not in the JSON). `pgvector` needs `table` and, for the default `native` backend, the table's `dim`; `"backend": "portable"` selects the JSON-text fallback table.
- Startup is fail closed: invalid JSON, a bad field, a missing `ales_adapters` package (an optional import; install or mount `adapters/` next to the server) or a missing client library (`redis`, `qdrant_client`, `sqlalchemy`) raises `ConfigError`. Store connections open lazily on the first purge, so a store that is down at boot does not stop the control plane; the failed row retries with backoff.
- Verification: after each target's idempotent delete the server re-checks that the object is gone and fails the row if it is still there (the outbox then retries). A purge for a superseded version leaves a newer version of the same `context_id` alone.
- `outbox_handlers=` passed to `create_app` still takes precedence over the environment.

Check the mode from `GET /v1/outbox/stats`, field `worker.handlers`: `log_only` means nothing is purged; `purge:<targets,...>` lists the wired stores; `custom` means a handler map passed in code.

**Outbox operations (admin role, tenant-scoped).**

| Call | Effect |
| --- | --- |
| `GET /v1/outbox/dead?limit=&after_id=` | Dead rows of the caller's tenant: `id, context_id, version, store_kind, attempts, last_error, created_at` (limit 1-500, default 100; page by `after_id`). |
| `POST /v1/outbox/dead/{id}/requeue` | `dead` to `pending`, attempts reset, due now; audited as `admin.outbox.requeue`. 404 for an unknown or other tenant's row, 409 if the row is not dead. |
| `POST /v1/outbox/run` | Run the dispatcher once now over the caller's tenant's due rows; returns `{leased, done, failed, dead, lost_lease}`. Safe next to the background worker (leasing is compare-and-swap). |

Dead-letter runbook: alert on `dead > 0` (`/v1/outbox/stats`), read `last_error` from `/v1/outbox/dead`, fix the store, requeue the rows, then `POST /v1/outbox/run` and confirm `dead` is back to 0.

## 5. Health and readiness

- `GET /v1/healthz`: unauthenticated, always `{"status": "ok"}`. It does not touch the database. Use as liveness.
- `GET /v1/readyz`: unauthenticated. Runs `SELECT 1` and compares the database revision to head. Returns 200 `{"status":"ready"}` when both pass, else 503 with `checks` (`database`: ok/unavailable, `migrations`: ok/behind/unavailable). Driver errors are not returned.

Both are in `EXEMPT_PATHS` in `auth.py`. Every other route needs a bearer token.

## 6. Monitoring

**Prometheus endpoint: `GET /v1/metrics`** (read role; defined in `governance.py`, rendered by `metrics.py`). Text format 0.0.4. Series: `ales_authorize_total`, `ales_revocations_total`, `ales_outbox_rows`, `ales_audit_records_total`, `ales_policy_active_info`, `ales_uptime_seconds`, plus three process-wide counters that are not tenant-scoped: `ales_denylist_rejections_total`, `ales_token_reloads_total{outcome="ok|error"}` and `ales_audit_export_failures_total`.

- **Counters are per process.** `authorize` and `revocation` counters reset on restart and differ between replicas. Aggregate with `sum()` in Prometheus. The outbox, audit and policy gauges are read from the database, so they match across replicas.
- **Tenant scope.** An authenticated scrape shows only the caller's tenant. With `ALES_METRICS_PUBLIC=1` the path is exempt from auth and renders sums over all tenants, so restrict network access to it. Leave the variable off unless the scraper cannot send a token.
- The Helm `serviceMonitor` is disabled by default and sends no bearer token, so a scrape needs `ALES_METRICS_PUBLIC=1` (set via `extraEnv`) or it fails with 401.

Other signals, which work without the metrics endpoint:

- **Decision log.** Each `/v1/authorize` writes one JSON line through logger `ales.server`, event `authorize`, with tenant, principal id, decision, reasons and trace id. Document content is not logged.
- **Outbox health.** `GET /v1/outbox/stats` (read role): totals, dead count, worker running flag, interval, handler mode.
- **Audit verify.** `GET /v1/audit/verify` (admin role), see section 7.
- **OpenTelemetry.** Spans `ales.authorize` and `ales.revocation` are created only when `opentelemetry-api` is importable (optional import in `telemetry.py`). Whether the image installs it is not checked here.
- **Readiness.** `/v1/readyz`.

Suggested alerts that the repo's signals support: readyz not 200; `dead > 0` in outbox stats; `worker.running == false` while `interval_seconds > 0`; audit verify `ok == false`. Thresholds are the operator's choice.

## 7. Audit chain verification

- Each tenant has a hash-chained `audit_log`. `GET /v1/audit/verify` (admin) verifies the tenant chain and its `:verify` scratch chain. It returns `{ok, first_bad_seq, records_checked}`.
- **Verification is read-only.** The call appends nothing and commits nothing (on Postgres it runs in a `READ ONLY` transaction), so checking the ledger never changes it.
- **Tail truncation is not detectable from the chain.** `core/ales_core/audit.py` says so. Defence is external anchoring. `GET /v1/audit/head` (read role) returns `{tenant_id, seq, head_hash, at}`: the newest record of the caller's tenant chain (`seq` 0 and the all-zero genesis hash for an empty chain) and the server time it was read. Poll it on a schedule into WORM storage or a signed log; a later head that does not extend an anchored one means truncation or rewrite.
- **Continuous export (`ALES_AUDIT_EXPORT_FILE`).** When set, every audit record is also appended, after its transaction commits, as one JSON line `{tenant_id, seq, prev_hash, hash, at, actor, action, detail}` to that file (opened in append mode per commit batch, fsync-ed). Records of rolled-back transactions are never written. An export failure is logged and increments `ales_audit_export_failures_total` but never fails the request, so a failing export leaves a visible gap in `seq` rather than an outage. **The file is the external anchor only if it lives on storage the database operator cannot rewrite** (separate host or volume, WORM / append-only mount, or shipped off-box by a log forwarder). On the same disk as the database it adds convenience, not tamper evidence.
- Cadence is not defined in the repo. Choose one, and treat a gap in anchors as an alert.
- `GET /v1/audit/verify` checks integrity only. Detail values are restricted by `_check_detail` at write time; the repo does not re-review them.

## 7b. Credential emergency: revoking an identity without a restart

Two file-based mechanisms act without the database and without redeploying. Both stat their file at request time at most once every 5 seconds and re-read only when its mtime or size changed.

- **Token registry hot reload.** With `ALES_TOKENS_FILE` set, edit or atomically replace the file: a new token works, and a removed token stops working, on the first request after the next poll. **Propagation bound: at most 5 s after the file changes (plus requests already in flight, which finish under the old registry).** The swap is atomic. A reload that fails to parse or validate is logged (`token reload failed`), counted (`ales_token_reloads_total{outcome="error"}`) and the previous registry stays in force, so a typo cannot lock everyone out. An empty valid file (`{}`) is applied and revokes every static token. Tokens passed through `ALES_TOKENS` (the env var) are fixed for the process lifetime; if a file is also configured, the env tokens are re-merged on every reload. Mounted Kubernetes Secrets/ConfigMaps update the file with their own kubelet delay (typically up to a minute) on top of the 5 s.
- **Denylist (`ALES_DENYLIST_FILE`).** JSON `{"subjects": [...], "jwt_subs": [...], "jwt_jtis": [...], "key_ids": [...]}`. A request whose static-token identity subject, or OIDC mapped subject, is in `subjects` gets 401 (the same body as any bad credential); `jwt_subs` applies to OIDC tokens only, and `jwt_jtis` revokes individual OIDC tokens by their `jti` claim. Rejections are logged and counted (`ales_denylist_rejections_total`). Use it to cut off one compromised identity immediately (an OIDC token is otherwise valid until `exp`) without rotating the whole token file. Startup with a missing or malformed file is a `ConfigError`; a malformed file on reload keeps the last good content and logs an error. The same 5 s propagation bound applies per process; each replica reads its own copy of the file, so distribute it to every replica.
- **Issuer keys are not in the denylist.** `key_ids` is accepted but not enforced (a warning is logged if it is non-empty). To stop trusting a signing key, `PATCH /v1/admin/keys/{key_id}` with `status: revoked`; that takes effect at signature ingress immediately because it lives in the database. It is not retroactive for objects already registered (R14).

## 8. Backups and restore

- The database is the single source of truth for envelopes, the derivation graph, tombstones, revocation events, the audit ledger and key registry. Downstream stores (vector indexes, caches, etc.) hold payloads and are purged from the outbox.
- Use Postgres point-in-time recovery from your platform. The repo contains no backup or restore tooling, and no restore drill has been run (`deploy/README.md`: "managed-DB backups are enabled but untested here").
- **Restore hazard.** Restoring to a point before a revocation event re-activates the source: its event, tombstones and epoch bump are rolled back. Treat every restore as a security event for revocation purposes.
- **Procedure (R22), tool `scripts/ales_restore_check.py`** (uses `DATABASE_URL` or `--database-url`):
  1. Before any incident, run `python scripts/ales_restore_check.py export --out /secure/revocations.jsonl` on a schedule (at least as often as your backup RPO) and ship the file off-box to storage the database operator cannot rewrite. It holds all revocation events, tombstones and the epoch per tenant, and complements `ALES_AUDIT_EXPORT_FILE` (section 7), whose `revocation.accept` records are also accepted as input.
  2. After a restore, keep the control plane out of rotation and run `verify --file /secure/revocations.jsonl`. Exit 1 lists missing events, tombstones and lagging epochs: that is the resurrection window.
  3. Run `reapply --file /secure/revocations.jsonl`. It re-accepts every missing event (idempotent by `event_id`, safe to repeat) and re-runs the comparison; exit 0 means no gaps remain. Run `verify` again and only then restore traffic.
  4. Stores that hold payloads are not restored from the same backup: reapplying enqueues new outbox rows, so let the purge targets run (`POST /v1/outbox/run`, then check `/v1/outbox/stats`).
  Limits: events accepted after the last export and lost with the database cannot be recovered from the file; objects registered after the restore point are lost (a re-applied event for an unknown source becomes a pending tombstone that applies if the source is registered again); events replayed from an audit export are unsigned and carry no `source_event_id`. No restore drill has been run against Postgres; the tool is tested on SQLite.

## 9. Connector freshness

The repo defines **no freshness SLA and no connector heartbeat**. Connectors are not health-checked by the server. `ConnectorRegistry.health_report()` and `freshness_guard` / `assert_fresh` (`connectors/`, R33) are primitives only: nothing in the server or SDK calls them. Available measures:

- Revocation propagation: each revocation is accepted synchronously; denial applies at the next authorize call on instrumented paths.
- Snapshot lease: `ALES_SNAPSHOT_LEASE` (server default 60 s) bounds offline use.
- SDK decision cache: `max_ttl` default 30 s; `max_clock_skew` default 30 s (`sdk-python/ales_sdk/decision_cache.py`).
- Outbox state per store kind via `/v1/outbox/stats`.

Set a freshness SLA for each connector in your own runbook. Derive it from the lease and cache TTLs above, not from any number in this repo.

## 10. Startup and deployment order

1. Create the Secret (DATABASE_URL, tokens, snapshot key). See `deploy/helm/ales-invariant/templates/NOTES.txt` for names.
2. Run migrations once (Helm hook Job, or manual `run_migrations`).
3. Start one replica, verify `/v1/readyz` and `/v1/snapshot/public_key` (`ephemeral: false`).
4. Scale to the desired replica count.
5. Verify `/v1/outbox/stats` `worker.handlers` is the mode you intended.

Terraform and Helm have not been run against real clouds or clusters (`deploy/README.md`). Run `terraform validate`, `helm lint` and `helm template` in CI before first use.

## 11. Commands

```
GET  /v1/healthz                 unauthenticated liveness
GET  /v1/readyz                  unauthenticated readiness (DB + migration head)
GET  /v1/snapshot/public_key     read
GET  /v1/snapshot                read; signed snapshot, Cache-Control: no-store
GET  /v1/outbox/stats            read (tenant-scoped totals, worker status)
GET  /v1/lineage/{context_id}    read
GET  /v1/audit/verify            admin; read-only (appends nothing)
GET  /v1/audit/head              read; {tenant_id, seq, head_hash, at} for external anchoring
GET  /v1/admin/keys              admin
POST /v1/admin/keys              admin
PATCH /v1/admin/keys/{key_id}    admin; status active|retired|revoked
GET  /v1/metrics                 read (or unauthenticated with ALES_METRICS_PUBLIC=1)
```

Other routes: `POST /v1/sources`, `POST /v1/derivations` (ingest), `POST /v1/revocations` (revoke), `POST /v1/authorize` (read), `POST /v1/verify` (**ingest**, self-test in `<tenant>:verify`; it registers objects and a revocation, so it is a write path and a read-only token gets 403). The v0.3 governance routes are in section 12.

## 12. v0.3 governance surface

Routes are in `server/ales_server/governance.py`. Each binds to the caller's tenant and takes the acting subject from the credential. Every mutation writes an audit record in the same transaction.

- **Policies (admin).** `POST /v1/policies` installs a policy document (201, audit `policy.install`). `POST /v1/policies/{policy_id}/versions/{version}/activate` makes one installed version the tenant's only active policy and deactivates the rest (`policy.activate`; rollback to an older installed version is allowed). `GET /v1/policies` lists versions, optionally filtered by `policy_id`. `GET /v1/policies/{policy_id}/versions/{version}` returns one document and its `active` flag. While a policy is active, `/v1/authorize` evaluates it and reports `policy_version` as `<policy_id>@<version>`.
- **Workloads and delegations.** `POST /v1/workloads` (admin, 201) registers a workload, `PATCH /v1/workloads/{workload_id}` (admin) changes its status or capabilities, and `GET /v1/workloads` (read) lists them. `POST /v1/delegations` (admin, 201) creates a delegation, `DELETE /v1/delegations/{delegation_id}` (admin) revokes it (`delegation.revoke`), and `GET /v1/delegations` (read) lists them. Grants: `POST /v1/workloads/{workload_id}/grants` with `{"principal_id": ...}` (admin, 201, idempotent, 404 for an unknown workload) lets a principal act as that workload (`workload.grant`), `DELETE /v1/workloads/{workload_id}/grants/{principal_id}` (admin, 404 if absent) removes it (`workload.grant_revoke`), and `GET /v1/grants?principal_id=` (read) lists them.
- **Handoffs (read).** `POST /v1/handoffs` with `from_workload`, `to_workload` and `purpose` asks whether an agent-to-agent handoff is allowed. A deny is a normal 200 with `decision` and `reason`, never a 404. Every answer is audited as `handoff.authorize`. If that audit write fails, the call fails and the decision is not served.
- **Approvals (admin to decide).** When a policy requires human review, `/v1/authorize` creates a pending approval, audited as `approval.request` with the authorizing caller as actor. `GET /v1/approvals?state=pending` (admin) lists pending approvals, and `GET /v1/approvals/{approval_id}` (read) shows one. `POST /v1/approvals/{approval_id}/decide` (admin) takes `{"approve": true|false, "ttl_seconds": N}`, where `N` is 1 to 2592000 (30 days). The decision is audited as `approval.decide`. Deciding an approval that is not pending returns 409. An approval covers only requests with the same fingerprint, and only until its `expires_at`. **Separation of duties:** `approval.request` stores both the requested principal (`principal.id` of the authorize call) and the requesting actor (token subject); `decide` returns 409 `{"detail": "separation of duties: decider matches requester"}` if the deciding subject equals either, for approve and deny. Approvals created before migration 0003 are not blocked. `ALES_APPROVAL_ALLOW_SELF=1` disables the check (dev or single-admin deployments only; logged at startup). Run the migration job to head (0003) before rolling the new server image. See R35 in `docs/residual-risks.md`.

### Workload enforcement and grants

`ALES_ENFORCE_WORKLOADS` selects how `/v1/authorize` treats a request that carries `agent_id`:

| Mode | Behaviour |
|---|---|
| `auto` (default) | Checked only once the tenant has registered at least one workload. Before that, `agent_id` is an unverified label. |
| `strict` | Always checked. An unknown or suspended agent is denied with `WORKLOAD_SUSPENDED` even when the tenant has no workloads, and requested tools must be in the agent's capabilities (`CAPABILITY_MISSING`). |
| `off` | No workload, capability or grant checks. The server logs a loud warning at startup. |

**Production should set `strict`**, so a tenant cannot believe agent identity is enforced when nothing is registered. Requests without `agent_id` are never workload-checked in any mode. The audit detail of each decision records `workload_gate` and, when not `auto`, `workload_enforcement`.

Grants are a second opt-in gate. When the gate applies, the agent is registered and active, and the tenant has recorded any grant, the requesting principal must hold a grant for that agent, otherwise the decision is DENY with `PRINCIPAL_NOT_IN_SCOPE` and audit detail `grant_missing: true`. Capability and suspension denials take precedence. A tenant with no grants keeps the previous behaviour, and revoking its last grant switches the check off again. Record a grant for every agent before relying on it. See R36. `ALES_REQUIRE_GRANTS=1` (default on under `ALES_ENV=production`) pins this gate: a principal without a grant for the agent is denied even when the tenant has no grant rows at all, so revoking the last grant no longer switches the check off. With it on, record a grant for every agent-acting principal before go-live.

### Policy risk floors

`risk` on `/v1/authorize` is caller-asserted and advisory. A policy document may carry `risk_floors`, for example `{"payments": "high", "*": "low"}` (values `low`, `medium`, `high`; keys are a purpose or `*`). The effective risk used to match a rule's `risk` is the maximum of the caller's risk, the floor for the request purpose and the `*` floor (`low < medium < high`); an absent caller risk counts as the floor. A caller can therefore raise risk but never lower it below a floor. With no applicable floor behaviour is unchanged. The floors are part of the policy document, so they are versioned and audited with it (`policy.install`, `policy.activate`). Treat floors, not the caller's `risk`, as the control. See R37.
