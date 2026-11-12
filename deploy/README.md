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
- Environment (the only variables the server reads): `DATABASE_URL` (`postgresql+psycopg://...?sslmode=require`),
  `ALES_TOKENS` / `ALES_TOKENS_FILE`, `ALES_REQUIRE_SIGNATURES` (prod: `1`), `ALES_SNAPSHOT_KEY` (base64 32-byte
  Ed25519 seed, identical on every replica), `ALES_SNAPSHOT_KEY_ID`, `ALES_SNAPSHOT_LEASE`, `ALES_MAX_BODY`,
  `ALES_OUTBOX_INTERVAL`.
- Fail closed: no tokens configured means protected routes answer 503; a malformed setting is a startup error;
  an unset snapshot key silently becomes an ephemeral per-process key, so **always set it** outside dev.
- Migrations: the server runs `alembic upgrade head` at start and cannot be told to skip it. Helm runs a
  pre-install/pre-upgrade Job first; Terraform targets document "deploy with one instance first" or a one-off task.

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
- WAF, DDoS tiers, API gateways, identity-provider integration (tokens are static bearer tokens from the registry).
- Metrics/dashboards/alerting: the server exposes no `/metrics` endpoint yet; the Helm ServiceMonitor is a disabled stub.
- Image build/publish pipeline and registry creation (you supply a pinned image; `deploy/Dockerfile` builds a dev image
  that runs as root; build a non-root production image before using targets that cannot force a non-root user).
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
  --set image.repository=registry.example.com/ales-invariant --set image.tag=0.2.0 \
  --set secrets.existingSecret=ales-prod \
  --set 'networkPolicy.egress.databaseCidrs={10.20.3.0/24}'
```
