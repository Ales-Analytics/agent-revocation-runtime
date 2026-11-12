# terraform/modules/core

Provider-neutral interface. It creates **no cloud resources** and declares **no providers**. It turns neutral
inputs into the runtime contract (env vars, secret references, ports, health paths) that every provider module
(`../../azure`, `../../aws`, `../../gcp`) consumes via `module "core" { source = "../modules/core" }`.

## Contract each provider module MUST satisfy

1. **Run the image** `output.image` with `output.replica_count` replicas, listening on `output.container_port`.
2. **Inject `plain_env`** verbatim as environment variables.
3. **Inject `secret_env_refs`** as secret-backed environment variables (`DATABASE_URL`, `ALES_SNAPSHOT_KEY`),
   resolved at runtime by the platform from the provider's secret store. Secret values never appear in env
   blocks in plain text, in outputs, or in container definitions checked into state beyond what the provider
   API forces (see each README's state note).
4. **Provide the token registry** (`tokens_secret_ref`) as a file at `ALES_TOKENS_FILE` where the platform can
   mount secrets as files, otherwise as `ALES_TOKENS` (JSON). Never both with overlapping tokens (the server
   rejects duplicates).
5. **Probes**: liveness `health_paths.liveness`, readiness `health_paths.readiness`.
6. **Network**: database reachable only over private networking; ingress only from the platform load balancer
   to `container_port`; DB accepts 5432 only from the service. TLS is required on the public edge.
7. **Identity**: the workload uses a dedicated identity (managed identity / task role / service account) with
   read access to exactly the three secrets and nothing else.
8. **Migrations**: the server migrates at startup and has no skip switch. Providers must run the service with
   one replica on first deploy of a schema change, or run a one-off migration task
   (`python -c "from sqlalchemy import create_engine; import os; from ales_core.migrations import run_migrations; run_migrations(create_engine(os.environ['DATABASE_URL']))"`)
   before scaling out. Provider READMEs document the exact step.
9. **Tagging**: every resource carries `tags`.
10. **Fail closed**: `require_signatures` defaults to true; a deployment without tokens answers 503 on protected
    routes, so provider modules must make the tokens secret mandatory.

## Interface

- Inputs: `variables.tf`. Secret **references** are plain strings (identifiers), not sensitive values; secret
  **values** are only ever accepted by provider modules, as `sensitive = true` variables.
- Outputs: `outputs.tf`.

Only environment variables read by `server/ales_server` are emitted; no invented variables.
