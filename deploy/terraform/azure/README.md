# terraform/azure

Container Apps (VNet-integrated) + PostgreSQL Flexible Server (private access, no public endpoint) +
Key Vault (RBAC, purge protection, private endpoint) + Log Analytics + user-assigned managed identity.
Consumes `../modules/core` for the neutral env/secret contract. (AKS users: use `deploy/helm` instead and
reuse only the network/database/Key Vault parts of this module.)

## Apply

```bash
export ARM_SUBSCRIPTION_ID=<guid>          # or az login + subscription_id variable
export TF_VAR_subscription_id=$ARM_SUBSCRIPTION_ID
export TF_VAR_tokens_json="$(cat tokens.json)"          # from your secret manager, never from a committed file
export TF_VAR_snapshot_key="$(python -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')"
terraform init -backend-config=backend.<env>.hcl        # per-environment azurerm backend (private storage account)
terraform plan  -var-file=<env>.tfvars -out tfplan      # tfvars hold NON-secret values only
terraform apply tfplan
```

Required non-secret vars: `subscription_id`, `location`, `environment`, `image`. See `variables.tf`.

### First deploy and schema changes (migration race)
The server runs `alembic upgrade head` at every start and has no switch to skip it; concurrent replicas can race.
Deploy with `-var replica_count=1` first (or whenever a release contains a schema change), wait for
`/v1/readyz` to report `migrations: ok`, then re-apply with the target replica count.

### Key Vault network access
The vault is private-endpoint-only by default. Terraform writes secrets over the data plane, so either run
Terraform from inside the VNet (self-hosted agent) or set `key_vault_allowed_ip_ranges=["<runner-public-ip>/32"]`
for the apply and remove it afterwards.

### Ingress / DNS
`public_ingress=false` (default) creates an internal environment: create a private DNS zone for
`environment_default_domain` pointing at `environment_static_ip`, or front it with your gateway.
HTTPS only; the platform terminates TLS with its default certificate. Custom domains/certs are out of scope.

### Private registry
Set `registry_server`; then grant the output `workload_identity_principal_id` the `AcrPull` role on the registry.

## Security notes
- The DB password is generated (`random_password`) and written to Key Vault. It also lives in Terraform state and
  the secret variables live in state: use an encrypted, access-controlled backend; never commit state or tfvars with secrets.
- Container Apps cannot enforce `readOnlyRootFilesystem`/`runAsNonRoot`; harden by building a non-root image.
- Workload identity has `Key Vault Secrets User` scoped to the three individual secrets only.
- All secrets are `sensitive` variables or generated; there are no default passwords.

## Permissions needed to apply
Principal running Terraform needs, on the target subscription/resource group:
- `Contributor` on the resource group (or subscription if the RG does not yet exist),
- `Role Based Access Control Administrator` (constrained to `Key Vault Secrets Officer` / `Key Vault Secrets User`)
  or `User Access Administrator`, to create the role assignments,
- Resource providers registered: `Microsoft.App`, `Microsoft.DBforPostgreSQL`, `Microsoft.KeyVault`,
  `Microsoft.Network`, `Microsoft.OperationalInsights`, `Microsoft.ManagedIdentity`,
- Backend: `Storage Blob Data Contributor` on the state container.
Runtime identity (created here): `Key Vault Secrets User` on three secrets; add `AcrPull` yourself if needed.

## Validation status
Not machine-validated in the authoring environment (terraform CLI unavailable): reviewed by hand only. Run
`terraform fmt -check && terraform init -backend=false && terraform validate` before first use.
