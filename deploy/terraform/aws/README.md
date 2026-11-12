# terraform/aws

ECS Fargate service behind an ALB (HTTPS only), Aurora PostgreSQL Serverless v2 in private subnets,
Secrets Manager (database URL, snapshot key, tokens) encrypted with a customer-managed KMS key, CloudWatch Logs,
VPC with private subnets, security groups, and VPC endpoints (no NAT gateway). Consumes `../modules/core`.
(EKS users: use `deploy/helm`; reuse only the network/database/secrets parts.)

## Apply

```bash
export AWS_PROFILE=<profile>                       # or OIDC-assumed role in CI
export TF_VAR_tokens_json="$(cat tokens.json)"     # from your secret manager; never a committed file
export TF_VAR_snapshot_key="$(python -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')"
terraform init -backend-config=backend.<env>.hcl   # per-environment S3 backend (encrypted, locked)
terraform plan  -var-file=<env>.tfvars -out tfplan # tfvars: NON-secret values only
terraform apply tfplan
```

Required non-secret vars: `region`, `environment`, `image` (ECR, same region), `acm_certificate_arn`,
`alb_ingress_cidrs`. The ACM certificate must already exist and be validated (issuance is out of scope).

### First deploy and schema changes (migration race)
The server runs `alembic upgrade head` at every start and has no skip switch; concurrent tasks can race.
Either apply with `-var replica_count=1` first and scale up after `/v1/readyz` reports `migrations: ok`, or run a
one-off task before scaling out:

```bash
aws ecs run-task --cluster "$(terraform output -raw cluster_name)" --launch-type FARGATE \
  --task-definition "$(terraform output -raw task_definition_arn)" \
  --network-configuration "awsvpcConfiguration={subnets=[$(terraform output -json private_subnet_ids | jq -r 'join(",")')],securityGroups=[$(terraform output -raw service_security_group_id)],assignPublicIp=DISABLED}" \
  --overrides '{"containerOverrides":[{"name":"ales-invariant","command":["python","-c","import os;from sqlalchemy import create_engine;from ales_core.migrations import run_migrations;run_migrations(create_engine(os.environ[\"DATABASE_URL\"]))"]}]}'
```

### Networking
- Tasks and Aurora have no public IPs. Ingress: `alb_ingress_cidrs` -> ALB:443 -> tasks:8787 -> Aurora:5432.
  The service SG accepts traffic only from the ALB SG; the DB SG only from the service SG.
- Egress to AWS APIs is via VPC endpoints (ECR, Secrets Manager, Logs, S3 gateway). The image must be in ECR in this region.
- `alb_internal=true` (default) creates an internal ALB; `false` adds public subnets and an IGW for the ALB only.
- No HTTP:80 listener is created. TLS policy `ELBSecurityPolicy-TLS13-1-2-2021-06`.

## Security notes
- Generated DB password and secret values are in Terraform state: encrypted, access-restricted backend only.
- Execution role can read exactly the three secrets and decrypt only via Secrets Manager; the task role has no permissions.
- Container runs as UID 10001 with read-only root filesystem and all capabilities dropped (image must tolerate that).
- Deletion protection is on by default for ALB and Aurora; set `alb_deletion_protection=false` / `db_deletion_protection=false` before destroying non-prod stacks.
- Secrets use a 30-day recovery window (names cannot be reused until it elapses).

## Permissions needed to apply
Principal running Terraform needs (scope to the target account/region; tighten to resource ARNs by prefix `ales-<env>`):
- EC2: `ec2:*Vpc*`, `*Subnet*`, `*RouteTable*`, `*Route`, `*InternetGateway*`, `*SecurityGroup*`, `*SecurityGroupRules*`,
  `*VpcEndpoint*`, `Describe*`, `CreateTags`, `DeleteTags`
- ECS: `ecs:*` on the cluster/service/task-definition; `application-autoscaling:*` for the service target/policy
- ELB: `elasticloadbalancing:*` (ALB, target group, listener)
- RDS: `rds:*` on cluster/instance/subnet/parameter groups; `rds:AddTagsToResource`
- KMS: `kms:CreateKey`, `CreateAlias`, `Describe*`, `Get*`, `PutKeyPolicy`, `EnableKeyRotation`, `TagResource`, `ScheduleKeyDeletion`
- Secrets Manager: `secretsmanager:CreateSecret`, `PutSecretValue`, `DescribeSecret`, `GetSecretValue`, `TagResource`, `DeleteSecret`, `GetResourcePolicy`
- Logs: `logs:CreateLogGroup`, `PutRetentionPolicy`, `AssociateKmsKey`, `DescribeLogGroups`, `TagResource`, `DeleteLogGroup`
- IAM: `iam:CreateRole`, `DeleteRole`, `GetRole`, `PutRolePolicy`, `DeleteRolePolicy`, `GetRolePolicy`, `TagRole`, `PassRole` (limited to the two created roles),
  `iam:CreateServiceLinkedRole` (ECS, RDS, ELB, autoscaling, first use per account)
- STS: `sts:GetCallerIdentity`; Backend: S3 read/write on the state bucket (+ lock table or lockfile).

## Validation status
Not machine-validated in the authoring environment (terraform CLI unavailable): reviewed by hand only. Run
`terraform fmt -check && terraform init -backend=false && terraform validate` before first use. Confirm
`aurora_engine_version` is available in your region (`aws rds describe-db-engine-versions --engine aurora-postgresql`).
