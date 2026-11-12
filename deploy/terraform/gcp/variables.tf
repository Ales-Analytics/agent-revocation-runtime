variable "project_id" {
  description = "GCP project ID."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project ID."
  }
}

variable "region" {
  description = "GCP region, e.g. europe-west1."
  type        = string

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "region must look like europe-west1."
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
  description = "Prefix for resource names (3-12 chars, lowercase alphanumeric/hyphen)."
  type        = string
  default     = "ales"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,10}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3-12 chars, lowercase alphanumeric or hyphen, starting with a letter."
  }
}

variable "image" {
  description = "Container image (Artifact Registry) pinned by tag or digest, never :latest."
  type        = string
}

variable "min_instances" {
  description = "Minimum Cloud Run instances. Use 1 (with max_instances=1) for the first deploy of any schema change (see README)."
  type        = number
  default     = 2

  validation {
    condition     = var.min_instances >= 0 && floor(var.min_instances) == var.min_instances
    error_message = "min_instances must be a non-negative integer."
  }
}

variable "max_instances" {
  description = "Maximum Cloud Run instances."
  type        = number
  default     = 6

  validation {
    condition     = var.max_instances >= 1
    error_message = "max_instances must be >= 1."
  }
}

variable "cpu" {
  description = "CPU limit per instance (e.g. \"1\")."
  type        = string
  default     = "1"
}

variable "memory" {
  description = "Memory limit per instance (e.g. \"512Mi\")."
  type        = string
  default     = "512Mi"
}

variable "ingress" {
  description = "Cloud Run ingress setting."
  type        = string
  default     = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  validation {
    condition     = contains(["INGRESS_TRAFFIC_ALL", "INGRESS_TRAFFIC_INTERNAL_ONLY", "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"], var.ingress)
    error_message = "ingress must be INGRESS_TRAFFIC_ALL, INGRESS_TRAFFIC_INTERNAL_ONLY or INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER."
  }
}

variable "allow_unauthenticated_invoker" {
  description = "Grant roles/run.invoker to allUsers so clients can reach the service without a Google IAM token (the app still enforces its own bearer tokens). Default false: callers need IAM. Combine true with a restrictive `ingress`."
  type        = bool
  default     = false
}

variable "invoker_members" {
  description = "IAM members (e.g. serviceAccount:x@p.iam.gserviceaccount.com) granted roles/run.invoker. Clients send the IAM token in X-Serverless-Authorization so Authorization stays free for the ALES bearer token."
  type        = list(string)
  default     = []
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
variable "connector_cidr" {
  description = "Unused /28 range for the Serverless VPC Access connector."
  type        = string
  default     = "10.8.0.0/28"

  validation {
    condition     = can(cidrhost(var.connector_cidr, 0)) && endswith(var.connector_cidr, "/28")
    error_message = "connector_cidr must be a valid /28 CIDR."
  }
}

variable "sql_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-custom-2-7680"
}

variable "sql_disk_size_gb" {
  description = "Cloud SQL disk size in GB."
  type        = number
  default     = 20
}

variable "sql_high_availability" {
  description = "Regional (HA) Cloud SQL instance; recommended for prod."
  type        = bool
  default     = false
}

variable "sql_backup_retained_count" {
  description = "Number of automated backups retained (>= 7)."
  type        = number
  default     = 14

  validation {
    condition     = var.sql_backup_retained_count >= 7
    error_message = "sql_backup_retained_count must be >= 7."
  }
}

variable "deletion_protection" {
  description = "Deletion protection for Cloud SQL and Cloud Run. Set false before destroying non-prod stacks."
  type        = bool
  default     = true
}

variable "labels" {
  description = "Extra labels applied to every resource that supports them."
  type        = map(string)
  default     = {}
}
