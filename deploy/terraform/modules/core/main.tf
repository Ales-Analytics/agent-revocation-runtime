# Provider-neutral core: pure computation, NO providers and NO cloud resources.
# Provider modules call this to obtain a single source of truth for env vars and the runtime contract.

locals {
  # Non-secret environment. Only variables read by server/ales_server/config.py (and snapshot/auth) are listed.
  plain_env = merge(
    {
      ALES_REQUIRE_SIGNATURES = var.require_signatures ? "1" : "0"
      ALES_OUTBOX_INTERVAL    = tostring(var.outbox_interval_seconds)
      ALES_SNAPSHOT_LEASE     = tostring(var.snapshot_lease_seconds)
      ALES_MAX_BODY           = tostring(var.max_body_bytes)
    },
    var.snapshot_key_id == "" ? {} : { ALES_SNAPSHOT_KEY_ID = var.snapshot_key_id }
  )

  # Secret-backed environment: env var name -> secret reference. Each provider maps the reference to its
  # native mechanism (Container Apps secretRef, ECS `secrets`, Cloud Run secret env).
  secret_env_refs = {
    DATABASE_URL      = var.database_url_secret_ref
    ALES_SNAPSHOT_KEY = var.snapshot_key_secret_ref
  }

  # The token registry is consumed as a FILE (ALES_TOKENS_FILE) or, for platforms that cannot mount secrets as
  # files, as the ALES_TOKENS env var (JSON). Providers choose; both are read by server/ales_server/auth.py.
  tokens_ref = var.tokens_secret_ref

  health = {
    liveness  = "/v1/healthz"
    readiness = "/v1/readyz"
  }
}
