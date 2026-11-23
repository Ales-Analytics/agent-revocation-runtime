# Compatibility matrix and policy

This page describes compatibility between components in this checkout and the policy for future releases. Registry availability is determined by the published package versions. Operational upgrade steps are in [upgrades.md](upgrades.md).

## Components at this revision

| Component | Version | Source |
|---|---|---|
| Python distribution | 0.3.0 | `pyproject.toml` |
| Server | 0.3.0 | `server/ales_server/main.py` |
| Spec | v0.4 | `spec/SPEC.md` |
| Alembic head | `0006` | `core/ales_core/alembic/versions/` |
| Python SDK | 0.2.0 | `sdk-python/ales_sdk/__init__.py` |
| TypeScript SDK | 0.2.0 | `sdk-typescript/package.json` |

The JSON schema IDs have a `/spec/v0.4/` version segment. The release history is in [the changelog](../CHANGELOG.md).

## Evidence behind the matrix

| Claim | Artifact | Notes |
|---|---|---|
| Enforcement across adapters | `conformance/report.md` (generated; summary shared with [coverage-matrix.md](coverage-matrix.md)) | Both files are generated from the same run. Live-store rows appear only when Qdrant, pgvector or Redis were reachable at generation time. |
| Revocation outcomes, both profiles | `benchmark/reports/latest.md`, `latest-postgres.md` | Recorded with a timestamp and source revision in each report header; regenerate at the release revision. |
| Concurrency on one host | `stress/` (`pytest -q stress`) | SQLite always; Postgres with `TEST_POSTGRES_URL`. See residual-risks R29 for what is not covered. |
| Client/server pairs | Intra-repo tests only | No third-party deployments. |

## Combination matrix

"Intra-repo" means the combination is designed and covered by tests in this repo. "Untested" means the design implies it works but no test pairs those versions.

| Client | Python distribution | 0.3.0 | `pyproject.toml` |
| Server | Status | What you get or lose |
|---|---|---|---|
| Python SDK 0.2.0 | 0.3.0 | Supported (intra-repo) | Full feature set, including `valid_until` handling, tools and risk fields. |
| TypeScript SDK 0.2.0 | 0.3.0 | Supported subset (intra-repo) | Source and derivation registration, revocation, authorization, lineage, verification and signed snapshots. Python exposes additional helpers, including release receipts and durable session reporting. |
| SDK older than 0.2.0 | 0.3.0 | Untested, expected to work | The server only adds fields, endpoints and reason codes. An older client ignores `valid_until` and sends no tools or risk data, so it gets v0.2 behaviour: TTL (`max_ttl` 30 s) plus clock-skew margin only, no policy-aware cutover. Unknown reason codes must be treated as deny for protected content (see below). No such SDK was ever released externally. |
| SDK 0.2.0 | Server older than 0.3.0 | Not supported | v0.3 request fields may be rejected (`extra="forbid"` on some models) and `valid_until` is absent. Pin client and server together. |
| Server at this revision | Database at Alembic `0006` | Required | `/v1/readyz` checks the exact Alembic head. |
| Server at this revision | Database behind `0006` | Migrate first | Readiness returns 503 when the database revision is behind. |
| Older server build | Database at `0006` | Verify before rollback | Readiness checks the exact head of the running build. See [upgrades](upgrades.md). |
| Connectors (`connectors/`) | Server 0.3.0 via Python SDK 0.2.0 | Supported (intra-repo) | Connectors call the server through `InvariantClient`; they inherit its compatibility. |

## Policy for future releases

These are commitments for releases that do not exist yet. They are not enforced by tooling today.

1. **Additive-only minors.** A minor release may add endpoints, optional request fields, response fields and enum values. It may not remove or rename them, tighten validation of existing fields, or change the meaning of an existing field.
2. **Reason codes are open.** Adding a reason code is non-breaking. Clients MUST treat any reason code they do not recognise as DENY for protected content, and may surface it as opaque text. A client that maps unknown reasons to ALLOW is non-conformant.
3. **Unknown response fields are ignored.** Clients must not fail on extra response fields. Servers may reject unknown request fields on models that declare `extra="forbid"`; this is why a newer client against an older server is unsupported.
4. **Schema `$id` version.** The version segment of a schema `$id` (`/spec/vN.M/`) changes only when the schema's shape changes in a way a validator could observe. Additive schema changes bump the minor segment and keep the previous `$id` resolvable. A breaking change requires a new major and is not allowed in a minor release.
5. **Database schema.** Migrations in a minor release must be backward compatible with the previous app version's queries. Readiness checks are exempt (they require the exact head), so a rolling upgrade still has a capacity dip; see [upgrades.md](upgrades.md).
6. **Deprecation window.** A feature, field or reason code is deprecated for at least one full minor version before removal, and removal happens only in a major release. The deprecation is recorded in `spec/SPEC.md` and in the release notes.
7. **Client and server skew.** The supported skew is one minor version with the client at the same or older minor. Newer client against older server is never supported.
8. **Pre-1.0 caveat.** Until 1.0, the spec major is 0 and the rules above are a goal, not a guarantee. Breaking changes may still occur, and each will be called out in `docs/upgrades.md`.
