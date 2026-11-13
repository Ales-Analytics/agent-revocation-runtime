# Deploying ALES INVARIANT

One application image, one neutral runtime contract, three ways to run it. No provider SDKs in the app; no lock-in.

| Target | Use when | Path |
|---|---|---|
| Docker Compose | Local dev, demos, CI smoke tests. Insecure by design (public dev token, unsigned envelopes allowed). | `docker-compose.yml` |
| Helm (any Kubernetes) | AKS, EKS, GKE, on-prem, kind. You already run a cluster and your own DB/secret tooling. | `helm/ales-invariant` |
| Terraform: Azure | No cluster; want Container Apps + PostgreSQL Flexible + Key Vault provisioned end to end. | `terraform/azure` |
| Terraform: AWS | No cluster; want ECS Fargate + ALB + Aurora Serverless v2 + Secrets Manager/KMS. | `terraform/aws` |
| Terraform: GCP | No cluster; want Cloud Run + Cloud SQL (private IP) + Secret Manager. | `terraform/gcp` |

`terraform/modules/core` is the provider-neutral interface (env vars, secret references, probes, ports) that every
provider module implements; read its README to add another provider.

## Runtime contract (all targets)
- Port 8787; liveness `/v1/healthz`, readiness `/v1/readyz` (DB reachable and schema at migration head). Both unauthenticated.
- Environment (main variables; the full list is in `docs/operations.md` section 1): `DATABASE_URL`
  (`postgresql+psycopg://...?sslmode=require`), `ALES_TOKENS` / `ALES_TOKENS_FILE`, `ALES_OIDC_CONFIG` (optional),
  `ALES_REQUIRE_SIGNATURES` (prod: `1`), `ALES_SNAPSHOT_KEY` (base64 32-byte Ed25519 seed, identical on every
  replica), `ALES_SNAPSHOT_KEY_ID`, `ALES_SNAPSHOT_LEASE`, `ALES_MAX_BODY`, `ALES_OUTBOX_INTERVAL`,
  `ALES_SKIP_STARTUP_MIGRATIONS`, `ALES_METRICS_PUBLIC`.
- Fail closed: no tokens configured means protected routes answer 503; a malformed setting is a startup error.
  With `ALES_REQUIRE_SIGNATURES=1` and no `ALES_SNAPSHOT_KEY`, startup is refused. With signatures off, an unset
  snapshot key becomes an ephemeral per-process key, so **always set it** outside dev.
- Migrations: the server runs `alembic upgrade head` at start unless `ALES_SKIP_STARTUP_MIGRATIONS=1` is set on the
  pod. Helm runs a pre-install/pre-upgrade Job first and does not set the skip variable; Terraform targets document
  "deploy with one instance first" or a one-off task.

## Secret-handling rules
1. Secrets are passed by **reference**. Kubernetes: `secrets.existingSecret`. Terraform: values enter only as
   `sensitive = true` variables via `TF_VAR_*` from your secret manager/CI secret store, or are generated
   (`random_password`); they are never in committed `.tfvars`, `values.yaml`, or the image.
2. Commit only non-secret `*.tfvars`/`values-*.yaml`; `deploy/.gitignore` excludes `*.auto.tfvars`, `secrets*.tfvars`,
   state and `.terraform/`.
3. Terraform state contains the generated DB password and secret values. Use a remote, encrypted, access-controlled,
   **per-environment** backend (`terraform init -backend-config=backend.<env>.hcl`); never a local state for shared envs.
4. No default passwords exist anywhere in the Terraform or Helm layers. `dev-tokens.json` and the compose
   `POSTGRES_PASSWORD` are public dev-only values; never reuse them.
5. Rotate: tokens and snapshot key by writing a new secret version and restarting; a snapshot key change invalidates
   outstanding snapshots, so publish the new public key to clients first.
6. Workload identities read exactly the three secrets (database URL, snapshot key, tokens) and nothing else.

## What is NOT provided
- TLS certificate issuance or renewal (guidance only: ACM / Key Vault certs / Google-managed certs / cert-manager; the
  modules take an existing certificate or use the platform default).
- DNS records or zones (outputs give you the target hostname).
- Multi-region, cross-region DR, or geo-replicated databases (single region, multi-AZ where the platform offers it).
- WAF, DDoS tiers, API gateways. Identity: static bearer tokens, or OIDC JWT verification with a static JWKS only
  (`ALES_OIDC_CONFIG`; no live JWKS fetch, see `docs/operations.md` section 2b).
- Dashboards and alerting. The server exposes Prometheus text at `/v1/metrics` (read role; `ALES_METRICS_PUBLIC=1`
  exempts it). The Helm ServiceMonitor is disabled by default and sends no bearer token.
- Image build/publish pipeline and registry creation (you supply a pinned image; `deploy/Dockerfile` runs as
  `USER 10001:10001` and installs runtime dependencies only. Confirm the container user on the image you deploy).
- Backup/restore drills; managed-DB backups are enabled but untested here.
- Machine validation in the authoring environment: neither `terraform` nor `helm` was available, so these were
  reviewed by hand. Run `terraform fmt -check && terraform validate` and `helm lint` + `helm template` in CI.

## Quick start (Helm, any cluster)
```bash
kubectl create secret generic ales-prod \
  --from-literal=database-url="$DATABASE_URL" \
  --from-file=tokens.json=./tokens.json \
  --from-literal=snapshot-key="$ALES_SNAPSHOT_KEY"
helm upgrade --install ales deploy/helm/ales-invariant \
  --set image.repository=registry.example.com/ales-invariant --set image.tag=0.3.0 \
  --set secrets.existingSecret=ales-prod \
  --set 'networkPolicy.egress.databaseCidrs={10.20.3.0/24}'
```
