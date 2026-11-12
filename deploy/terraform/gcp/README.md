# terraform/gcp

Cloud Run (v2) service reaching Cloud SQL PostgreSQL 16 over **private IP only** through a Serverless VPC Access
connector, Secret Manager (database URL, snapshot key, tokens), and a dedicated least-privilege runtime service
account. Consumes `../modules/core`. (GKE users: use `deploy/helm`; reuse the network/database/secrets parts.)

## Apply

```bash
gcloud auth application-default login             # or workload identity federation in CI
export TF_VAR_tokens_json="$(cat tokens.json)"    # from your secret manager; never a committed file
export TF_VAR_snapshot_key="$(python -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')"
terraform init -backend-config=backend.<env>.hcl  # per-environment GCS backend
terraform plan  -var-file=<env>.tfvars -out tfplan # tfvars: NON-secret values only (project_id, region, environment, image)
terraform apply tfplan
```

### First deploy and schema changes (migration race)
The server runs `alembic upgrade head` at every start and has no skip switch; concurrent instances can race.
Apply once with `-var min_instances=1 -var max_instances=1`, wait until the revision is ready (the startup probe
uses `/v1/readyz`, which reports `migrations: ok`), then re-apply with the target scaling.

### Reaching the service
Default: `ingress=INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER` and no public invoker. Put a (global/regional) external or
internal HTTPS load balancer with a serverless NEG in front (TLS certificates and DNS are out of scope), and either
set `allow_unauthenticated_invoker=true` (the app still demands its own bearer token) or list callers in
`invoker_members` and have them send the Google ID token in `X-Serverless-Authorization`, leaving `Authorization`
for the ALES bearer token.

### Image pull
Cloud Run pulls with the Cloud Run service agent (`service-<project-number>@serverless-robot-prod.iam.gserviceaccount.com`).
Grant it `roles/artifactregistry.reader` on your repository if the image is in another project or repo.

## Security notes
- Cloud SQL: no public IP, `ENCRYPTED_ONLY`, PITR on, deletion protection on. The generated DB password and secret
  values live in Terraform state: use a private, versioned GCS bucket with restricted IAM; never commit state/tfvars with secrets.
- Secrets use user-managed replication pinned to `region`; the runtime SA gets `secretAccessor` per secret only.
- The env var `DATABASE_URL` etc. resolve from Secret Manager `latest`; rotate by adding a version and redeploying.
- Set `deletion_protection=false` before destroying non-prod stacks.

## Permissions needed to apply
Principal running Terraform needs on the project:
- `roles/serviceusage.serviceUsageAdmin` (enable APIs),
- `roles/compute.networkAdmin` (VPC, global address, peering) and `roles/servicenetworking.networksAdmin`,
- `roles/vpcaccess.admin` (connector),
- `roles/cloudsql.admin`,
- `roles/secretmanager.admin` (create secrets, versions, per-secret IAM),
- `roles/iam.serviceAccountAdmin` + `roles/iam.serviceAccountUser` (create and attach the runtime SA),
- `roles/run.admin` (service and invoker IAM),
- Backend: `roles/storage.objectAdmin` on the state bucket.
Runtime SA (created here): `secretmanager.secretAccessor` on three secrets; nothing else.

## Validation status
Not machine-validated in the authoring environment (terraform CLI unavailable): reviewed by hand only. Run
`terraform fmt -check && terraform init -backend=false && terraform validate` before first use.
