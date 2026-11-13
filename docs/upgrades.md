# Upgrades, compatibility and rollback

What changes between versions, in what order to deploy, and what rollback really costs. Facts come from `spec/SPEC.md`, `core/alembic/versions/`, `server/ales_server/` and `deploy/`. Anything not verified by a run is marked as such.

## Versions

| Component | Current value in repo | Source |
|---|---|---|
| Spec | v0.3 (`spec/SPEC.md`) | SPEC header |
| Server app version | `0.3.0` | `server/ales_server/main.py` (`FastAPI(version=...)`) |
| Helm chart | `version: 0.3.0`, `appVersion: "0.3.0"` | `deploy/helm/ales-invariant/Chart.yaml` |
| Package metadata | `0.1.0` | `pyproject.toml` |
| Alembic head | `0003` | `core/alembic/versions/0003_approval_separation_of_duties.py` |
| Deploy docs example | image tag `0.3.0` | `deploy/README.md` |
| Last benchmark | git revision `1f0a228` (both profiles) | `benchmark/reports/latest.md`, `latest-postgres.md` |
| Schema `$id` | `/spec/v0.3/` | `spec/*.schema.json` |
| Changelog | `[0.3.0] - Unreleased` | [`CHANGELOG.md`](../CHANGELOG.md) |

The server, the chart's `appVersion` and spec v0.3 now agree, but package metadata remains at `0.1.0`. A version string still does not establish schema compatibility. Use Alembic head `0003` for that, and the spec version for protocol compatibility.

## Spec compatibility (v0.1 -> v0.2 -> v0.3)

- **v0.1 -> v0.2.** Adds bearer-token auth with tenant binding and roles, signed policy snapshots (`/v1/snapshot`, `/v1/snapshot/public_key`), the invalidation outbox, `effective_at` and `affected_scope` on revocations, and the audit ledger. Schema and API additions only. Migration `0001` is the initial schema and already contains the v0.2 tables (`audit_log`, `invalidation_outbox`, `issuer_keys`, `revocation_events`, `tombstones`, `tenants`).
- **v0.2 -> v0.3.** Adds policy documents, workloads, grants, delegations and approvals (migration `0002`), separation-of-duties fields for approvals (migration `0003`), new reason codes (`POLICY_DENIED`, `POLICY_HUMAN_REVIEW`, `APPROVAL_PENDING`, `APPROVAL_DENIED`, `DELEGATION_MISSING`, `WORKLOAD_SUSPENDED`, `CAPABILITY_MISSING`), and `valid_until` on authorize responses.
- **Server features in v0.3 (no additional schema change).** OIDC JWT verification (`ALES_OIDC_CONFIG`, static JWKS or live `jwks_uri`), `GET /v1/metrics`, the `ALES_SKIP_STARTUP_MIGRATIONS` switch, and the governance routes in `docs/operations.md` section 12.
- **Authorize evaluates installed policy.** `/v1/authorize` applies the tenant's active policy document when one exists, and `policy_version` becomes `<policy_id>@<version>`. With no active policy it stays `p0`. Decisions made under different policy versions are not comparable without this field.
- **OIDC supports static and live JWKS.** A live `jwks_uri` refreshes on its configured TTL and unknown key IDs, with a bounded stale-key window when refresh fails. There is no token revocation list; see [R13](residual-risks.md#r13-oidc-has-no-token-revocation-list). Test a JWT-authenticated call on the target image before depending on OIDC in an upgrade.
- **Additive by construction for 0002.** Migration `0002` only creates five new tables and their indexes. It alters no existing table or column.

## Alembic path

- `0001` (initial) -> `0002` (policy, workloads, approvals) -> `0003` (approval separation of duties). Upgrade with `run_migrations(engine)` (head) or a specific revision.
- Fresh database: `0001`, `0002`, then `0003`, in one run at head.
- Downgrade to `0002` removes the approval requester fields. Downgrade to `0001` also drops `approvals`, `delegations`, `workload_grants`, `workloads` and `policy_documents`. `downgrade_migrations(engine)` (base) also drops every v0.2 table, including `audit_log`, `revocation_events`, `tombstones`, `issuer_keys`, `context_objects` and `derivation_edges`. **Never downgrade to base on a database that holds data you need.**

## Zero-downtime upgrade order

The repo supports this order. Zero downtime is not verified (see the caveat below).

1. Take a verified database backup (section 8 of `docs/operations.md`). Confirm PITR is available.
2. Ensure the new image is pinned by digest. Helm: `image.digest`.
3. Run the migration. With Helm this is the `pre-install,pre-upgrade` hook Job (`templates/migration-job.yaml`), which runs `run_migrations` first. Without Helm, run `run_migrations` once from a one-off task.
4. Roll the pods. Helm `rolloutStrategy` is `maxUnavailable: 0, maxSurge: 1`.
5. Verify `/v1/readyz` (`database: ok`, `migrations: ok`) and `/v1/snapshot/public_key` (`ephemeral: false`).

**Caveat: readiness during a rolling upgrade.** `/v1/readyz` requires the database revision to equal the head compiled into the running image. After step 3, old pods (image head `0001`) see the database at `0003` and return 503 `migrations: behind`. Kubernetes then marks them NotReady while the new pods come up. This follows from `routes.py` and `migrations.py`. It has not been tested. Expect reduced capacity during the rollout, and test it in staging before relying on the order above. There is no repo mechanism to avoid it. A maintenance window, or a rollout at `replicaCount: 1`, avoids the question.

**Schema compatibility rule.** `deploy/helm/ales-invariant/templates/NOTES.txt` says schema changes must be backward compatible with the previous app version. Migrations `0002` and `0003` add tables or columns that `0001` code does not use. Readiness is not backward compatible, as above.

## SDK and server compatibility

See [compatibility.md](compatibility.md) for the version matrix and the policy for future releases.

- **Older SDK, newer server.** Supported by the design: the server only adds fields and endpoints. An old SDK ignores `valid_until` and the v0.3 reason codes. Confirm against your SDK version before relying on this.
- **Newer SDK, older server.** v0.3 request fields may be rejected by a v0.2 server if its models forbid unknown fields (`RevocationEvent` does, `extra="forbid"`; the v0.2 request models were not all checked). `valid_until` is absent from v0.2 responses, so the SDK's `valid_until` cutover cannot apply. The SDK then relies on its TTL (`max_ttl` 30 s) and clock-skew margin (30 s) only. Pin SDK and server together until you have tested the pair.
- TypeScript SDK (`sdk-typescript/`) is not covered by this document.

## Rollback

Rollback has two parts, and the second one destroys data.

1. **Image rollback alone does not work with a v0.3 schema.** The v0.2 image has head `0001`. Against a database at `0003` its `/v1/readyz` returns `migrations: behind`, so its pods never become ready. Image-only rollback is not a valid option after migration `0002` has run.
2. **Schema downgrade to `0001`** drops the v0.3 tables and columns. This is data loss:
   - `policy_documents`: all policy versions. Any decisions that depended on an installed policy lose their basis for review.
   - `workloads`, `workload_grants`, `delegations`: all identities, grants and handoff delegations. Any handoff authorization stops applying.
   - `approvals`: all approval records, including approved and denied decisions and the audit-relevant state that went with them. The audit ledger records the admin actions, but the approval rows themselves are gone.
   Downgrade to `0002` also removes the separation-of-duties requester fields from approval records.
   Before downgrading, export these tables. The repo has no export tool for them.
3. Then roll the image back to the previous digest.

Recommended: roll forward. Fix forward with a new image rather than downgrading the schema, unless the v0.3 feature is the cause of the incident.

Rollback to base (`0000`/none) is not a supported operation for any database that has served traffic. It also drops `audit_log`, so the audit chain would be lost. Do not run it. Restore from backup if that is ever required, with the restore hazard in `docs/operations.md` section 8.

**Rollback is not rehearsed.** No downgrade has been run against Postgres in this repo's evidence. Rehearse it in staging with a copy of production data before you need it.

## Checklist for every release

- Note the Alembic head and whether the release adds a migration.
- Note whether the tenant has an active policy before and after the release: `policy_version` changes with it.
- If a migration is present: confirm the readiness caveat above, decide on the rollout approach, and export data for any table the release drops or rewrites.
- Re-run the RevocationBench and conformance suites. `benchmark/reports/latest.md` and `latest-postgres.md` record revision `1f0a228`, which predates later commits, and must be regenerated at the release revision for any release that changes enforcement. Also run `pytest -q stress` (concurrency; set `TEST_POSTGRES_URL` for the Postgres parametrisation).
- Confirm `GET /v1/outbox/stats` shows the intended `worker.handlers` mode after the upgrade.
