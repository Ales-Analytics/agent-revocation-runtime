# Operations

Operator guide for running the ALES INVARIANT control plane (server 0.3.0). Everything here is taken from the code in this repo. Where the code and the deploy docs disagree, the code is the authority. Known gaps are in `docs/residual-risks.md`.

## 1. Required environment

Read by `server/ales_server/config.py`, `main.py`, `auth.py` and `snapshot.py`. Unset values fall back to the defaults shown.

| Variable | Default if unset | Production setting | Notes |
|---|---|---|---|
| `DATABASE_URL` | `sqlite:///./invariant.db` | `postgresql+psycopg://...?sslmode=require` | **If unset the server silently uses a SQLite file in the working directory.** Always set it. |
| `ALES_TOKENS` | none | JSON object, or use the file form | `{token: {tenant_id, roles, subject}}`. Roles: `ingest`, `revoke`, `read`, `admin`. Tokens are stored as SHA-256 digests in memory. |
| `ALES_TOKENS_FILE` | none | path to the JSON above (Helm/Terraform mount it) | Same token must not appear in both sources. |
| `ALES_DEV_ALLOW_ANONYMOUS` | off | never | Dev only. Every caller gets all roles and chooses its tenant. Ignored when tokens are configured. |
| `ALES_REQUIRE_SIGNATURES` | **off** (`config.py` default) | `1` | Helm defaults it to `1`. With it off, unsigned envelopes and revocations are accepted. |
| `ALES_SNAPSHOT_KEY` | none (ephemeral key generated) | base64 raw 32-byte Ed25519 seed, identical on every replica | Required when signatures are on, see section 2. |
| `ALES_SNAPSHOT_KEY_ID` | derived from public key | optional | |
| `ALES_ALLOW_EPHEMERAL_SNAPSHOT_KEY` | off | leave off | Overrides the startup refusal below. Each process then signs with its own key. |
| `ALES_SNAPSHOT_LEASE` | `60` (seconds, integer >= 1) | set deliberately | Lease written into every snapshot. This is the server-side input to the bounded-offline exposure window. |
| `ALES_MAX_BODY` | `1048576` bytes | as needed | Body cap, enforced before authentication. |
| `ALES_OUTBOX_INTERVAL` | `5.0` seconds | as needed | `0` disables the background outbox worker. |
| `ALES_SKIP_STARTUP_MIGRATIONS` | off | `1` on pods that run behind a migration job, see section 3 | Read by `main.py`. The Helm chart does not set it. |
| `ALES_OIDC_CONFIG` | off | JSON, see section 2b | Enables OIDC JWT verification alongside the static tokens. |
| `ALES_METRICS_PUBLIC` | off | leave off | `1` exempts `GET /v1/metrics` from auth and makes it render cross-tenant sums. See section 6. |

Malformed values (non-numeric, bad booleans, bad JSON, bad base64 keys, duplicate tokens, unknown roles, tenant ids ending in `:verify`) are startup errors. No tokens configured means protected routes return 503.

Helm, `deploy/helm/ales-invariant/templates/configmap.yaml`, sets `ALES_REQUIRE_SIGNATURES`, `ALES_OUTBOX_INTERVAL`, `ALES_SNAPSHOT_LEASE`, `ALES_MAX_BODY`, `ALES_SNAPSHOT_KEY_ID` (optional) and `ALES_TOKENS_FILE`. `DATABASE_URL` and `ALES_SNAPSHOT_KEY` come from the referenced Secret.

Production checklist:

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
 "jwks_file": "/run/ales/jwks.json",
 "claim_mapping": {"tenant_id": "org_id", "subject": "sub", "roles": "ales_roles"}}
```

- Exactly one of `jwks` (inline `{"keys": [...]}`) or `jwks_file`. Keys load once at startup. **Static JWKS only**: there is no `jwks_uri` fetch, so a key rotation at the IdP needs a restart. A live fetch is a known follow-up.
- Algorithms: `RS256` (RSA >= 2048 bits) and `ES256` (P-256) only. `none`, `HS*` and `crit` headers are rejected.
- `iss` must equal `issuer` exactly, `aud` must contain `audience`, and `exp` is required. Clock skew allowance is 60 s.
- `claim_mapping.roles` is a claim name, or `{"static": ["read"]}` to give every token from that issuer fixed roles. Identity comes only from mapped claims; a missing or malformed one is a 401. Roles must be known roles (`ingest`, `revoke`, `read`, `admin`).
- When OIDC is on, a bearer token shaped like a JWT is verified as OIDC and is never looked up in `ALES_TOKENS`. Every failure is a 401. Other tokens go to the static registry, if one is configured.
- The verifier keeps no revocation list. A token stays valid until its `exp`. To cut off a subject, stop issuing tokens at the IdP and wait out the token lifetime.
- Malformed config (bad JSON, missing issuer or audience, both or neither of `jwks`/`jwks_file`, unknown static roles) is a startup error.

## 3. Database and migrations

Schema is managed only by Alembic (`core/alembic/`, programmatic helpers in `core/ales_core/migrations.py`):

- `0001` initial schema: audit_log, invalidation_outbox, issuer_keys, revocation_events, tenants, tombstones, context_objects, derivation_edges.
- `0002` policy_documents, workloads, workload_grants, delegations, approvals (SPEC v0.3).
- `head_revision()` is the newest script in the image. `current_revision(engine)` is what the database is at. `run_migrations(engine, revision="head")` upgrades. `downgrade_migrations(engine, revision="base")` downgrades. See `docs/upgrades.md` before using downgrade.

**Startup migrations.** `create_app()` runs `run_migrations(engine)` on every process start unless `ALES_SKIP_STARTUP_MIGRATIONS=1` is set. Set it only on pods whose schema is migrated first by something else. `/v1/readyz` still reports `migrations: behind` until the schema reaches head.

**Helm.** `templates/migration-job.yaml` is a `pre-install,pre-upgrade` hook Job (weight -5) that runs `run_migrations` once before the Deployment rolls. Its settings are `migrations.enabled` (default true), `backoffLimit: 2` and `activeDeadlineSeconds: 600`. If the Job fails, the release fails. Logs: `kubectl logs job/<release>-migrate`.

**Race.** `run_migrations` has no advisory lock or other cross-process guard in the repo. When several replicas start against a database that is behind head, their Alembic runs can race. The hook Job avoids this for Helm releases. Outside Helm, either run migrations once out of band before starting replicas, or start one replica first and then scale. Do not start a fresh database with several replicas at once.

**Readiness depends on revision.** `/v1/readyz` returns `migrations: behind` unless the database revision equals the image's head. Expect any pod whose image head differs from the database revision to report NotReady. See `docs/upgrades.md`.

**Startup on Helm.** Pods run `run_migrations` at start unless `ALES_SKIP_STARTUP_MIGRATIONS=1` is set. The chart does not set it and has no values flag for it, so pods run the migration as a no-op at head. Adding such a flag would be a template change.

**Postgres driver.** The Helm migration Job calls `create_engine(DATABASE_URL)` directly. The app uses `pool_pre_ping=True` on non-SQLite URLs. Use `postgresql+psycopg://`.

## 4. Outbox worker and purge handlers

The background worker (`server/ales_server/worker.py`) runs when `ALES_OUTBOX_INTERVAL > 0` and the database is not in-memory SQLite. Each tick calls `OutboxDispatcher.run_once()`, then waits the interval. Rows are leased (60 s lease), retried with backoff (1, 5, 30, 120, 600 s), and dead-lettered after 6 failed attempts (`core/ales_core/outbox.py`).

**The shipped app has no real purge handlers.** `server/ales_server/main.py` ends with `app = create_app()`. Without `outbox_handlers`, the handler map is `{"*": log_only_handler}`. That handler logs that a purge is due and purges nothing, then the row is marked `done`. Use-time decisions do not depend on purge, so safety holds, but physical cleanup does not happen.

To wire real stores, build the app yourself:

Build a `PurgeRegistry` from `adapters/ales_adapters/purge.py` (register one purge handler per store kind; see that module for its constructor), then pass it to the app factory in a custom entrypoint:

```python
from ales_server.main import create_app
app = create_app(outbox_handlers=registry)   # registry: a PurgeRegistry with your store handlers
```

The module-level `app` in `main.py` cannot be changed by environment variables; a custom entrypoint is required.

Check the mode from `GET /v1/outbox/stats`, field `worker.handlers`. `log_only` means nothing is purged. `purge:<targets,...>` lists the wired stores. `custom` means some other handler map.

Dead letters: `GET /v1/outbox/stats` returns `totals` (pending, leased, done, dead) and `dead`. The repo has no endpoint to list or requeue dead rows. Recovery is a direct database operation, and it should be designed before the first incident.

## 5. Health and readiness

- `GET /v1/healthz`: unauthenticated, always `{"status": "ok"}`. It does not touch the database. Use as liveness.
- `GET /v1/readyz`: unauthenticated. Runs `SELECT 1` and compares the database revision to head. Returns 200 `{"status":"ready"}` when both pass, else 503 with `checks` (`database`: ok/unavailable, `migrations`: ok/behind/unavailable). Driver errors are not returned.

Both are in `EXEMPT_PATHS` in `auth.py`. Every other route needs a bearer token.

## 6. Monitoring

**Prometheus endpoint: `GET /v1/metrics`** (read role; defined in `governance.py`, rendered by `metrics.py`). Text format 0.0.4. Series: `ales_authorize_total`, `ales_revocations_total`, `ales_outbox_rows`, `ales_audit_records_total`, `ales_policy_active_info`, `ales_uptime_seconds`.

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
- **The call writes a record** (`admin.audit.verify`) to the chain each time it runs.
- **Tail truncation is not detectable from the chain.** `core/ales_core/audit.py` says so. Defence is external anchoring: export `ales_core.audit.head(session, tenant)` (returns `(seq, hash)`) periodically to WORM storage or a signed log. **No HTTP route returns the head.** Anchoring is an in-process or direct-database task today.
- Cadence is not defined in the repo. Choose one, and treat a gap in anchors as an alert.
- `GET /v1/audit/verify` checks integrity only. Detail values are restricted by `_check_detail` at write time; the repo does not re-review them.

## 8. Backups and restore

- The database is the single source of truth for envelopes, the derivation graph, tombstones, revocation events, the audit ledger and key registry. Downstream stores (vector indexes, caches, etc.) hold payloads and are purged from the outbox.
- Use Postgres point-in-time recovery from your platform. The repo contains no backup or restore tooling, and no restore drill has been run (`deploy/README.md`: "managed-DB backups are enabled but untested here").
- **Restore hazard.** Restoring to a point before a revocation event re-activates the source: its tombstone and epoch are rolled back. Any revocation accepted after the restore point must be re-submitted, and the restored state must be checked against the revocation log you hold outside the database. Treat a restore as a security event for revocation purposes. Retain revocation events outside the database if you need to prove re-application.
- Stores that hold payloads (caches, indexes) are not restored from the same backup as the control plane without a re-purge. Re-run revocations after any restore, then confirm with `/v1/outbox/stats`.

## 9. Connector freshness

The repo defines **no freshness SLA and no connector heartbeat**. Connectors are not health-checked by the server. Available measures:

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
GET  /v1/audit/verify            admin; writes an audit record
GET  /v1/admin/keys              admin
POST /v1/admin/keys              admin
PATCH /v1/admin/keys/{key_id}    admin; status active|retired|revoked
GET  /v1/metrics                 read (or unauthenticated with ALES_METRICS_PUBLIC=1)
```

Other routes: `POST /v1/sources`, `POST /v1/derivations` (ingest), `POST /v1/revocations` (revoke), `POST /v1/authorize` (read), `POST /v1/verify` (read, self-test in `<tenant>:verify`). The v0.3 governance routes are in section 12.

## 12. v0.3 governance surface

Routes are in `server/ales_server/governance.py`. Each binds to the caller's tenant and takes the acting subject from the credential. Every mutation writes an audit record in the same transaction.

- **Policies (admin).** `POST /v1/policies` installs a policy document (201, audit `policy.install`). `POST /v1/policies/{policy_id}/versions/{version}/activate` makes one installed version the tenant's only active policy and deactivates the rest (`policy.activate`; rollback to an older installed version is allowed). `GET /v1/policies` lists versions, optionally filtered by `policy_id`. `GET /v1/policies/{policy_id}/versions/{version}` returns one document and its `active` flag. While a policy is active, `/v1/authorize` evaluates it and reports `policy_version` as `<policy_id>@<version>`.
- **Workloads and delegations.** `POST /v1/workloads` (admin, 201) registers a workload, `PATCH /v1/workloads/{workload_id}` (admin) changes its status or capabilities, and `GET /v1/workloads` (read) lists them. `POST /v1/delegations` (admin, 201) creates a delegation, `DELETE /v1/delegations/{delegation_id}` (admin) revokes it (`delegation.revoke`), and `GET /v1/delegations` (read) lists them. Grants are audited as `workload.grant` and `workload.grant_revoke`.
- **Handoffs (read).** `POST /v1/handoffs` with `from_workload`, `to_workload` and `purpose` asks whether an agent-to-agent handoff is allowed. A deny is a normal 200 with `decision` and `reason`, never a 404. Every answer is audited as `handoff.authorize`. If that audit write fails, the call fails and the decision is not served.
- **Approvals (admin to decide).** When a policy requires human review, `/v1/authorize` creates a pending approval, audited as `approval.request` with the authorizing caller as actor. `GET /v1/approvals?state=pending` (admin) lists pending approvals, and `GET /v1/approvals/{approval_id}` (read) shows one. `POST /v1/approvals/{approval_id}/decide` (admin) takes `{"approve": true|false, "ttl_seconds": N}`, where `N` is 1 to 2592000 (30 days). The decision is audited as `approval.decide`. Deciding an approval that is not pending returns 409. An approval covers only requests with the same fingerprint, and only until its `expires_at`. There is no separation of duties: the decider may be the requester. See R35 in `docs/residual-risks.md`.
