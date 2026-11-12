variable "region" {
  description = "AWS region."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.region))
    error_message = "region must look like eu-west-1."
  }
}

variable "environment" {
  description = "Environment label (dev, staging, prod)."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of dev, staging, prod."
  }
}

variable "name_prefix" {
  description = "Prefix for resource names (3-16 chars, lowercase alphanumeric/hyphen)."
  type        = string
  default     = "ales"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,14}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3-16 chars, lowercase alphanumeric or hyphen, starting with a letter."
  }
}

variable "image" {
  description = "Container image URI pinned by tag or digest, in an ECR repo in this region (no NAT is created; pulls use VPC endpoints)."
  type        = string
}

variable "replica_count" {
  description = "Desired/minimum task count. Use 1 for the first deployment of any schema change (see README: migration race)."
  type        = number
  default     = 2

  validation {
    condition     = var.replica_count >= 1 && floor(var.replica_count) == var.replica_count
    error_message = "replica_count must be a positive integer."
  }
}

variable "max_replicas" {
  description = "Autoscaling maximum task count."
  type        = number
  default     = 6

  validation {
    condition     = var.max_replicas >= 1
    error_message = "max_replicas must be >= 1."
  }
}

variable "task_cpu" {
  description = "Fargate task CPU units."
  type        = number
  default     = 512

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096], var.task_cpu)
    error_message = "task_cpu must be one of 256, 512, 1024, 2048, 4096."
  }
}

variable "task_memory" {
  description = "Fargate task memory (MiB); must be a valid pairing with task_cpu."
  type        = number
  default     = 1024
}

# ---- Edge ----
variable "acm_certificate_arn" {
  description = "ARN of an existing ACM certificate in this region for the ALB HTTPS listener (issuance/validation is out of scope)."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:acm:[a-z0-9-]+:[0-9]{12}:certificate/.+$", var.acm_certificate_arn))
    error_message = "acm_certificate_arn must be a valid ACM certificate ARN."
  }
}

variable "alb_internal" {
  description = "true (default) creates an internal ALB in private subnets; false creates an internet-facing ALB (adds public subnets + IGW)."
  type        = bool
  default     = true
}

variable "alb_ingress_cidrs" {
  description = "CIDRs allowed to reach the ALB on 443. Must be set explicitly; there is no default-open."
  type        = list(string)

  validation {
    condition     = length(var.alb_ingress_cidrs) > 0 && alltrue([for c in var.alb_ingress_cidrs : can(cidrhost(c, 0))])
    error_message = "alb_ingress_cidrs must be a non-empty list of valid CIDRs."
  }
}

variable "alb_deletion_protection" {
  description = "Enable ALB deletion protection."
  type        = bool
  default     = true
}

# ---- Secrets (values from TF_VAR_* or a secrets-aware pipeline; never committed) ----
variable "tokens_json" {
  description = "JSON token registry content (ALES_TOKENS): {\"<token>\": {\"tenant_id\":..., \"roles\":[...], \"subject\":...}}."
  type        = string
  sensitive   = true

  validation {
    condition     = can(jsondecode(var.tokens_json)) && length(keys(try(jsondecode(var.tokens_json), {}))) > 0
    error_message = "tokens_json must be a non-empty JSON object (value hidden)."
  }
}

variable "snapshot_key" {
  description = "ALES_SNAPSHOT_KEY: standard base64 of a raw 32-byte Ed25519 seed (44 chars). Generate: python -c \"import os,base64;print(base64.b64encode(os.urandom(32)).decode())\""
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[A-Za-z0-9+/]{43}=$", var.snapshot_key))
    error_message = "snapshot_key must be standard base64 of exactly 32 bytes (value hidden)."
  }
}

# ---- Server config ----
variable "require_signatures" {
  description = "ALES_REQUIRE_SIGNATURES. Keep true in production."
  type        = bool
  default     = true
}

variable "snapshot_lease_seconds" {
  description = "ALES_SNAPSHOT_LEASE."
  type        = number
  default     = 60
}

variable "outbox_interval_seconds" {
  description = "ALES_OUTBOX_INTERVAL."
  type        = number
  default     = 5
}

variable "max_body_bytes" {
  description = "ALES_MAX_BODY."
  type        = number
  default     = 1048576
}

variable "snapshot_key_id" {
  description = "ALES_SNAPSHOT_KEY_ID (optional)."
  type        = string
  default     = ""
}

# ---- Network / data ----
variable "vpc_cidr" {
  description = "VPC CIDR; must be a /16 (subnets are derived)."
  type        = string
  default     = "10.50.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0)) && endswith(var.vpc_cidr, "/16")
    error_message = "vpc_cidr must be a valid /16 CIDR."
  }
}

variable "az_count" {
  description = "Number of availability zones (2 or 3)."
  type        = number
  default     = 2

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 3
    error_message = "az_count must be 2 or 3."
  }
}

variable "aurora_engine_version" {
  description = "Aurora PostgreSQL engine version (Serverless v2 capable, major 16)."
  type        = string
  default     = "16.4"

  validation {
    condition     = can(regex("^16\\.", var.aurora_engine_version))
    error_message = "aurora_engine_version must be a 16.x version (the parameter group family is aurora-postgresql16)."
  }
}

variable "aurora_min_acu" {
  description = "Serverless v2 minimum capacity (ACU)."
  type        = number
  default     = 0.5
}

variable "aurora_max_acu" {
  description = "Serverless v2 maximum capacity (ACU)."
  type        = number
  default     = 8
}

variable "aurora_instance_count" {
  description = "Number of Aurora instances (1 writer, additional readers across AZs). Use >= 2 for production."
  type        = number
  default     = 2

  validation {
    condition     = var.aurora_instance_count >= 1 && var.aurora_instance_count <= 4
    error_message = "aurora_instance_count must be between 1 and 4."
  }
}

variable "db_backup_retention_days" {
  description = "Aurora backup retention (7-35)."
  type        = number
  default     = 14

  validation {
    condition     = var.db_backup_retention_days >= 7 && var.db_backup_retention_days <= 35
    error_message = "db_backup_retention_days must be between 7 and 35."
  }
}

variable "db_deletion_protection" {
  description = "Enable Aurora deletion protection."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 90

  validation {
    condition     = contains([30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a CloudWatch-supported retention value >= 30."
  }
}

variable "tags" {
  description = "Extra tags applied to every resource."
  type        = map(string)
  default     = {}
}
