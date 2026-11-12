data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

resource "random_password" "db_master" {
  length  = 32
  special = false # keeps the connection URL simple; entropy comes from length
}

locals {
  base = "${var.name_prefix}-${var.environment}"

  tags = merge(var.tags, {
    application = "ales-invariant"
    environment = var.environment
    managed-by  = "terraform"
  })

  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  private_cidrs = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i)]
  public_cidrs  = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, 8 + i)]

  db_name        = "invariant"
  db_master_user = "alesadmin"
}

# ------------------------------------------------------------------------------------------ KMS (CMK)
resource "aws_kms_key" "this" {
  description             = "ALES INVARIANT ${var.environment}: secrets, logs, database encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # Default key policy (account root delegates to IAM). Principals are granted via IAM policies below and the
  # CloudWatch Logs service principal statement.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMPolicies"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/ecs/${local.base}*"
          }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "this" {
  name          = "alias/${local.base}"
  target_key_id = aws_kms_key.this.key_id
}

# ------------------------------------------------------------------------------------------ network
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "vpc-${local.base}" }
}

resource "aws_subnet" "private" {
  count             = var.az_count
  vpc_id            = aws_vpc.this.id
  cidr_block        = local.private_cidrs[count.index]
  availability_zone = local.azs[count.index]
  tags              = { Name = "private-${local.base}-${local.azs[count.index]}" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "rt-private-${local.base}" }
}

resource "aws_route_table_association" "private" {
  count          = var.az_count
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Public subnets + IGW exist only for an internet-facing ALB. Tasks and the database never get public IPs and
# there is no NAT gateway: egress to AWS APIs uses VPC endpoints below.
resource "aws_internet_gateway" "this" {
  count  = var.alb_internal ? 0 : 1
  vpc_id = aws_vpc.this.id
  tags   = { Name = "igw-${local.base}" }
}

resource "aws_subnet" "public" {
  count                   = var.alb_internal ? 0 : var.az_count
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.public_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false
  tags                    = { Name = "public-${local.base}-${local.azs[count.index]}" }
}

resource "aws_route_table" "public" {
  count  = var.alb_internal ? 0 : 1
  vpc_id = aws_vpc.this.id
  tags   = { Name = "rt-public-${local.base}" }
}

resource "aws_route" "public_internet" {
  count                  = var.alb_internal ? 0 : 1
  route_table_id         = aws_route_table.public[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[0].id
}

resource "aws_route_table_association" "public" {
  count          = var.alb_internal ? 0 : var.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

# ---- security groups: ingress only ALB -> service, service -> db 5432 ----
resource "aws_security_group" "alb" {
  name        = "${local.base}-alb"
  description = "ALES ALB"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${local.base}-alb" }
}

resource "aws_security_group" "service" {
  name        = "${local.base}-service"
  description = "ALES ECS tasks"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${local.base}-service" }
}

resource "aws_security_group" "db" {
  name        = "${local.base}-db"
  description = "ALES Aurora"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${local.base}-db" }
}

resource "aws_security_group" "endpoints" {
  name        = "${local.base}-endpoints"
  description = "VPC interface endpoints"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${local.base}-endpoints" }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each          = toset(var.alb_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from allowed clients"
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_service" {
  security_group_id            = aws_security_group.alb.id
  description                  = "ALB to tasks"
  referenced_security_group_id = aws_security_group.service.id
  from_port                    = module.core.container_port
  to_port                      = module.core.container_port
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "service_from_alb" {
  security_group_id            = aws_security_group.service.id
  description                  = "From ALB only"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = module.core.container_port
  to_port                      = module.core.container_port
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "service_to_db" {
  security_group_id            = aws_security_group.service.id
  description                  = "Tasks to Aurora"
  referenced_security_group_id = aws_security_group.db.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "service_to_endpoints" {
  security_group_id            = aws_security_group.service.id
  description                  = "Tasks to interface endpoints (ECR, Secrets Manager, Logs)"
  referenced_security_group_id = aws_security_group.endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "service_to_s3" {
  security_group_id = aws_security_group.service.id
  description       = "Tasks to S3 via gateway endpoint (ECR image layers)"
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "db_from_service" {
  security_group_id            = aws_security_group.db.id
  description                  = "PostgreSQL from tasks only"
  referenced_security_group_id = aws_security_group.service.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_service" {
  security_group_id            = aws_security_group.endpoints.id
  description                  = "HTTPS from tasks"
  referenced_security_group_id = aws_security_group.service.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

# ---- VPC endpoints (no NAT) ----
resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(["ecr.api", "ecr.dkr", "secretsmanager", "logs"])
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "vpce-${local.base}-${each.value}" }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = { Name = "vpce-${local.base}-s3" }
}

# ------------------------------------------------------------------------------------------ database
resource "aws_db_subnet_group" "this" {
  name       = local.base
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_rds_cluster_parameter_group" "this" {
  name   = "${local.base}-pg16"
  family = "aurora-postgresql16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_rds_cluster" "this" {
  cluster_identifier              = local.base
  engine                          = "aurora-postgresql"
  engine_mode                     = "provisioned"
  engine_version                  = var.aurora_engine_version
  database_name                   = local.db_name
  master_username                 = local.db_master_user
  master_password                 = random_password.db_master.result
  db_subnet_group_name            = aws_db_subnet_group.this.name
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.this.name
  vpc_security_group_ids          = [aws_security_group.db.id]
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.this.arn
  backup_retention_period         = var.db_backup_retention_days
  copy_tags_to_snapshot           = true
  deletion_protection             = var.db_deletion_protection
  skip_final_snapshot             = false
  final_snapshot_identifier       = "${local.base}-final"
  enabled_cloudwatch_logs_exports = ["postgresql"]

  serverlessv2_scaling_configuration {
    min_capacity = var.aurora_min_acu
    max_capacity = var.aurora_max_acu
  }
}

resource "aws_rds_cluster_instance" "this" {
  count                 = var.aurora_instance_count
  identifier            = "${local.base}-${count.index}"
  cluster_identifier    = aws_rds_cluster.this.id
  engine                = aws_rds_cluster.this.engine
  engine_version        = aws_rds_cluster.this.engine_version
  instance_class        = "db.serverless"
  db_subnet_group_name  = aws_db_subnet_group.this.name
  publicly_accessible   = false
  copy_tags_to_snapshot = true
}

# ------------------------------------------------------------------------------------------ secrets
resource "aws_secretsmanager_secret" "database_url" {
  name                    = "${local.base}/database-url"
  kms_key_id              = aws_kms_key.this.arn
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id = aws_secretsmanager_secret.database_url.id
  secret_string = format(
    "postgresql+psycopg://%s:%s@%s:5432/%s?sslmode=require",
    local.db_master_user,
    urlencode(random_password.db_master.result),
    aws_rds_cluster.this.endpoint,
    local.db_name,
  )
}

resource "aws_secretsmanager_secret" "snapshot_key" {
  name                    = "${local.base}/snapshot-key"
  kms_key_id              = aws_kms_key.this.arn
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret_version" "snapshot_key" {
  secret_id     = aws_secretsmanager_secret.snapshot_key.id
  secret_string = var.snapshot_key
}

resource "aws_secretsmanager_secret" "tokens" {
  name                    = "${local.base}/tokens"
  kms_key_id              = aws_kms_key.this.arn
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret_version" "tokens" {
  secret_id     = aws_secretsmanager_secret.tokens.id
  secret_string = var.tokens_json
}

# ------------------------------------------------------------------------------------------ neutral core contract
module "core" {
  source = "../modules/core"

  name                    = local.base
  image                   = var.image
  replica_count           = var.replica_count
  database_url_secret_ref = aws_secretsmanager_secret.database_url.arn
  tokens_secret_ref       = aws_secretsmanager_secret.tokens.arn
  snapshot_key_secret_ref = aws_secretsmanager_secret.snapshot_key.arn
  require_signatures      = var.require_signatures
  snapshot_lease_seconds  = var.snapshot_lease_seconds
  outbox_interval_seconds = var.outbox_interval_seconds
  max_body_bytes          = var.max_body_bytes
  snapshot_key_id         = var.snapshot_key_id
  tags                    = local.tags
}
