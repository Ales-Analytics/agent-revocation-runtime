output "resource_group" {
  description = "Resource group name."
  value       = azurerm_resource_group.this.name
}

output "app_fqdn" {
  description = "Container App FQDN (internal to the VNet unless public_ingress=true)."
  value       = azurerm_container_app.this.ingress[0].fqdn
}

output "environment_default_domain" {
  description = "Container Apps environment default domain (create a private DNS zone for it when ingress is internal)."
  value       = azurerm_container_app_environment.this.default_domain
}

output "environment_static_ip" {
  description = "Container Apps environment inbound IP."
  value       = azurerm_container_app_environment.this.static_ip_address
}

output "key_vault_name" {
  description = "Key Vault holding database-url, snapshot-key and ales-tokens."
  value       = azurerm_key_vault.this.name
}

output "workload_identity_principal_id" {
  description = "Principal ID of the app's user-assigned managed identity (grant AcrPull here if you use a private registry)."
  value       = azurerm_user_assigned_identity.app.principal_id
}

output "postgres_fqdn" {
  description = "Private FQDN of the PostgreSQL Flexible Server."
  value       = azurerm_postgresql_flexible_server.this.fqdn
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace resource ID."
  value       = azurerm_log_analytics_workspace.this.id
}
