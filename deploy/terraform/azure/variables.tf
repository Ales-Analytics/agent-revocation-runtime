variable "subscription_id" {
  description = "Azure subscription ID to deploy into."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.subscription_id))
    error_message = "subscription_id must be a GUID."
  }
}

variable "location" {
  description = "Azure region, e.g. westeurope."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]+$", var.location))
    error_message = "location must be a lowercase region name without spaces (e.g. westeurope)."
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
  description = "Short prefix for resource names (3-12 chars, lowercase alphanumeric/hyphen)."
  type        = string
  default     = "ales"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,10}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3-12 chars, lowercase alphanumeric or hyphen, starting with a letter."
  }
}

variable "image" {
  description = "Container image pinned by tag or digest (never :latest)."
  type        = string
}

variable "registry_server" {
  description = "Optional private registry login server (e.g. myacr.azurecr.io). The workload identity is used to pull; grant it AcrPull on the registry yourself. Empty means a public registry."
  type        = string
  default     = ""
}

variable "replica_count" {
  description = "Minimum replicas. Use 1 for the first deployment of any schema change (see README: migration race)."
  type        = number
  default     = 2

  validation {
    condition     = var.replica_count >= 1 && floor(var.replica_count) == var.replica_count
    error_message = "replica_count must be a positive integer."
  }
}

variable "max_replicas" {
  description = "Maximum replicas for autoscaling."
  type        = number
  default     = 6

  validation {
    condition     = var.max_replicas >= 1
    error_message = "max_replicas must be >= 1."
  }
}

variable "cpu" {
  description = "vCPU per replica (Container Apps allowed combinations apply)."
  type        = number
  default     = 0.5
}

variable "memory" {
  description = "Memory per replica, e.g. 1Gi (must pair with cpu)."
  type        = string
  default     = "1Gi"
}

variable "public_ingress" {
  description = "true exposes the app on a public endpoint (HTTPS only); false (default) makes the environment internal to the VNet."
  type        = bool
  default     = false
}

# ---- Secrets: values come from TF_VAR_* env vars or a secrets-manager-driven pipeline. Never commit them. ----
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
variable "vnet_cidr" {
  description = "VNet address space; must be a /16 (subnets are derived)."
  type        = string
  default     = "10.40.0.0/16"

  validation {
    condition     = can(cidrhost(var.vnet_cidr, 0)) && endswith(var.vnet_cidr, "/16")
    error_message = "vnet_cidr must be a valid /16 CIDR."
  }
}

variable "key_vault_allowed_ip_ranges" {
  description = "Public IPs/CIDRs allowed to reach the Key Vault data plane (needed when Terraform runs outside the VNet). Empty means private endpoint only; then Terraform must run inside the VNet."
  type        = list(string)
  default     = []
}

variable "postgres_sku_name" {
  description = "PostgreSQL Flexible Server SKU."
  type        = string
  default     = "GP_Standard_D2ds_v5"
}

variable "postgres_storage_mb" {
  description = "Storage in MB."
  type        = number
  default     = 32768
}

variable "postgres_backup_retention_days" {
  description = "Backup retention (7-35)."
  type        = number
  default     = 14

  validation {
    condition     = var.postgres_backup_retention_days >= 7 && var.postgres_backup_retention_days <= 35
    error_message = "postgres_backup_retention_days must be between 7 and 35."
  }
}

variable "postgres_high_availability" {
  description = "Enable zone-redundant HA (recommended for prod)."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Log Analytics retention in days (30-730)."
  type        = number
  default     = 30

  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 730
    error_message = "log_retention_days must be between 30 and 730."
  }
}

variable "tags" {
  description = "Extra tags applied to every resource."
  type        = map(string)
  default     = {}
}
