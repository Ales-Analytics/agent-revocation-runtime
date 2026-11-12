terraform {
  required_version = ">= 1.5.0, < 2.0.0"
}

variable "name" {
  description = "Deployment name prefix (lowercase, DNS-label safe)."
  type        = string
  default     = "ales-invariant"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}[a-z0-9]$", var.name))
    error_message = "name must be 3-32 chars, lowercase alphanumeric or hyphen, starting with a letter."
  }
}

variable "image" {
  description = "Fully qualified container image, pinned by tag or (preferably) digest. No implicit latest."
  type        = string

  validation {
    condition     = can(regex("(@sha256:[a-f0-9]{64}|:[A-Za-z0-9._-]+)$", var.image)) && !endswith(var.image, ":latest")
    error_message = "image must include an explicit tag or @sha256 digest and must not be :latest."
  }
}

variable "replica_count" {
  description = "Desired (minimum) number of replicas. >= 2 recommended for availability."
  type        = number
  default     = 2

  validation {
    condition     = var.replica_count >= 1 && floor(var.replica_count) == var.replica_count
    error_message = "replica_count must be a positive integer."
  }
}

variable "container_port" {
  description = "Port the server listens on (uvicorn in deploy/Dockerfile)."
  type        = number
  default     = 8787
}

# ---- Secret REFERENCES. These are identifiers of secrets (ARNs, Key Vault secret URIs, Secret Manager IDs),
# ---- never the secret values. Provider modules create/own the secrets; this module only carries the contract.
variable "database_url_secret_ref" {
  description = "Reference (not value) of the secret that holds DATABASE_URL (postgresql+psycopg://...)."
  type        = string
}

variable "tokens_secret_ref" {
  description = "Reference (not value) of the secret that holds the JSON token registry (ALES_TOKENS_FILE content)."
  type        = string
}

variable "snapshot_key_secret_ref" {
  description = "Reference (not value) of the secret that holds ALES_SNAPSHOT_KEY (base64 raw 32-byte Ed25519 seed)."
  type        = string
}

# ---- Non-secret server configuration (mirrors server/ales_server/config.py) ----
variable "require_signatures" {
  description = "ALES_REQUIRE_SIGNATURES. Keep true in production."
  type        = bool
  default     = true
}

variable "snapshot_lease_seconds" {
  description = "ALES_SNAPSHOT_LEASE (seconds, >= 1)."
  type        = number
  default     = 60

  validation {
    condition     = var.snapshot_lease_seconds >= 1 && floor(var.snapshot_lease_seconds) == var.snapshot_lease_seconds
    error_message = "snapshot_lease_seconds must be an integer >= 1."
  }
}

variable "outbox_interval_seconds" {
  description = "ALES_OUTBOX_INTERVAL (seconds; 0 disables the background worker)."
  type        = number
  default     = 5

  validation {
    condition     = var.outbox_interval_seconds >= 0
    error_message = "outbox_interval_seconds must be >= 0."
  }
}

variable "max_body_bytes" {
  description = "ALES_MAX_BODY (bytes, >= 1)."
  type        = number
  default     = 1048576

  validation {
    condition     = var.max_body_bytes >= 1 && floor(var.max_body_bytes) == var.max_body_bytes
    error_message = "max_body_bytes must be an integer >= 1."
  }
}

variable "snapshot_key_id" {
  description = "ALES_SNAPSHOT_KEY_ID. Empty means the server derives one from the public key."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags/labels applied to every resource by provider modules."
  type        = map(string)
  default     = {}
}
