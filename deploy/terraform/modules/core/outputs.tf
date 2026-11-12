output "plain_env" {
  description = "Non-secret environment variables for the server container."
  value       = local.plain_env
}

output "secret_env_refs" {
  description = "Map of env var name to secret reference (DATABASE_URL, ALES_SNAPSHOT_KEY)."
  value       = local.secret_env_refs
}

output "tokens_secret_ref" {
  description = "Reference of the token-registry secret (mount as file at ALES_TOKENS_FILE, or inject as ALES_TOKENS)."
  value       = local.tokens_ref
}

output "container_port" {
  description = "Server port."
  value       = var.container_port
}

output "image" {
  description = "Container image."
  value       = var.image
}

output "replica_count" {
  description = "Desired replica count."
  value       = var.replica_count
}

output "health_paths" {
  description = "Liveness and readiness HTTP paths (unauthenticated)."
  value       = local.health
}

output "tags" {
  description = "Tags to apply to all resources."
  value       = var.tags
}
