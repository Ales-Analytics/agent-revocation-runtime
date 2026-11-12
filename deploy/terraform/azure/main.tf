data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
}

resource "random_password" "db_admin" {
  length  = 32
  special = false # keeps the connection URL simple; entropy comes from length
}

locals {
  suffix = random_string.suffix.result
  base   = "${var.name_prefix}-${var.environment}"

  tags = merge(var.tags, {
    application = "ales-invariant"
    environment = var.environment
    managed-by  = "terraform"
  })

  db_admin_login = "alesadmin"
  db_name        = "invariant"

  subnet_pg  = cidrsubnet(var.vnet_cidr, 8, 0)
  subnet_pe  = cidrsubnet(var.vnet_cidr, 8, 1)
  subnet_aca = cidrsubnet(var.vnet_cidr, 7, 1) # /23, no overlap with the two /24 above

  # Env var name -> Container Apps secret name (lowercase, hyphenated).
  secret_names = { for env, _ in module.core.secret_env_refs : env => lower(replace(env, "_", "-")) }
}

resource "azurerm_resource_group" "this" {
  name     = "rg-${local.base}"
  location = var.location
  tags     = local.tags
}

# ------------------------------------------------------------------------------------------ observability
resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-${local.base}-${local.suffix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.tags
}

# ------------------------------------------------------------------------------------------ network
resource "azurerm_virtual_network" "this" {
  name                = "vnet-${local.base}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [var.vnet_cidr]
  tags                = local.tags
}

resource "azurerm_subnet" "postgres" {
  name                 = "snet-postgres"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [local.subnet_pg]

  delegation {
    name = "postgres-flexible"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [local.subnet_pe]
}

resource "azurerm_subnet" "containerapps" {
  name                 = "snet-containerapps"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [local.subnet_aca]
}

resource "azurerm_private_dns_zone" "postgres" {
  name                = "${local.base}-${local.suffix}.private.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "link-postgres"
  resource_group_name   = azurerm_resource_group.this.name
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = azurerm_virtual_network.this.id
  tags                  = local.tags
}

resource "azurerm_private_dns_zone" "keyvault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "keyvault" {
  name                  = "link-keyvault"
  resource_group_name   = azurerm_resource_group.this.name
  private_dns_zone_name = azurerm_private_dns_zone.keyvault.name
  virtual_network_id    = azurerm_virtual_network.this.id
  tags                  = local.tags
}

# ------------------------------------------------------------------------------------------ database
resource "azurerm_postgresql_flexible_server" "this" {
  name                          = "${local.base}-pg-${local.suffix}"
  resource_group_name           = azurerm_resource_group.this.name
  location                      = azurerm_resource_group.this.location
  version                       = "16"
  sku_name                      = var.postgres_sku_name
  storage_mb                    = var.postgres_storage_mb
  backup_retention_days         = var.postgres_backup_retention_days
  geo_redundant_backup_enabled  = false
  delegated_subnet_id           = azurerm_subnet.postgres.id
  private_dns_zone_id           = azurerm_private_dns_zone.postgres.id
  public_network_access_enabled = false
  administrator_login           = local.db_admin_login
  administrator_password        = random_password.db_admin.result
  tags                          = local.tags

  dynamic "high_availability" {
    for_each = var.postgres_high_availability ? [1] : []
    content {
      mode = "ZoneRedundant"
    }
  }

  lifecycle {
    ignore_changes = [zone]
  }

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]
}

resource "azurerm_postgresql_flexible_server_database" "this" {
  name      = local.db_name
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

# ------------------------------------------------------------------------------------------ identity + Key Vault
resource "azurerm_user_assigned_identity" "app" {
  name                = "id-${local.base}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_key_vault" "this" {
  name                          = "${var.name_prefix}-kv-${local.suffix}"
  location                      = azurerm_resource_group.this.location
  resource_group_name           = azurerm_resource_group.this.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 30
  public_network_access_enabled = length(var.key_vault_allowed_ip_ranges) > 0
  tags                          = local.tags

  network_acls {
    default_action = "Deny"
    bypass         = "None"
    ip_rules       = var.key_vault_allowed_ip_ranges
  }
}

resource "azurerm_private_endpoint" "keyvault" {
  name                = "pe-${local.base}-kv"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  tags                = local.tags

  private_service_connection {
    name                           = "kv"
    private_connection_resource_id = azurerm_key_vault.this.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "kv"
    private_dns_zone_ids = [azurerm_private_dns_zone.keyvault.id]
  }
}

# The identity running Terraform needs to write secrets (least privilege: Secrets Officer on this vault only).
resource "azurerm_role_assignment" "deployer_secrets_officer" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_key_vault_secret" "database_url" {
  name         = "database-url"
  key_vault_id = azurerm_key_vault.this.id
  value = format(
    "postgresql+psycopg://%s:%s@%s:5432/%s?sslmode=require",
    local.db_admin_login,
    urlencode(random_password.db_admin.result),
    azurerm_postgresql_flexible_server.this.fqdn,
    local.db_name,
  )
  content_type = "text/plain"
  tags         = local.tags

  depends_on = [azurerm_role_assignment.deployer_secrets_officer, azurerm_private_endpoint.keyvault]
}

resource "azurerm_key_vault_secret" "snapshot_key" {
  name         = "snapshot-key"
  key_vault_id = azurerm_key_vault.this.id
  value        = var.snapshot_key
  content_type = "text/plain"
  tags         = local.tags

  depends_on = [azurerm_role_assignment.deployer_secrets_officer, azurerm_private_endpoint.keyvault]
}

resource "azurerm_key_vault_secret" "tokens" {
  name         = "ales-tokens"
  key_vault_id = azurerm_key_vault.this.id
  value        = var.tokens_json
  content_type = "application/json"
  tags         = local.tags

  depends_on = [azurerm_role_assignment.deployer_secrets_officer, azurerm_private_endpoint.keyvault]
}

# Workload identity may read exactly these three secrets (scoped per secret, not per vault).
resource "azurerm_role_assignment" "app_database_url" {
  scope                = azurerm_key_vault_secret.database_url.resource_manager_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_role_assignment" "app_snapshot_key" {
  scope                = azurerm_key_vault_secret.snapshot_key.resource_manager_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_role_assignment" "app_tokens" {
  scope                = azurerm_key_vault_secret.tokens.resource_manager_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

# ------------------------------------------------------------------------------------------ neutral core contract
module "core" {
  source = "../modules/core"

  name                    = "${var.name_prefix}-${var.environment}"
  image                   = var.image
  replica_count           = var.replica_count
  database_url_secret_ref = azurerm_key_vault_secret.database_url.versionless_id
  tokens_secret_ref       = azurerm_key_vault_secret.tokens.versionless_id
  snapshot_key_secret_ref = azurerm_key_vault_secret.snapshot_key.versionless_id
  require_signatures      = var.require_signatures
  snapshot_lease_seconds  = var.snapshot_lease_seconds
  outbox_interval_seconds = var.outbox_interval_seconds
  max_body_bytes          = var.max_body_bytes
  snapshot_key_id         = var.snapshot_key_id
  tags                    = local.tags
}

# ------------------------------------------------------------------------------------------ compute
resource "azurerm_container_app_environment" "this" {
  name                           = "cae-${local.base}"
  location                       = azurerm_resource_group.this.location
  resource_group_name            = azurerm_resource_group.this.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.this.id
  infrastructure_subnet_id       = azurerm_subnet.containerapps.id
  internal_load_balancer_enabled = !var.public_ingress
  tags                           = local.tags
}

resource "azurerm_container_app" "this" {
  name                         = "ca-${local.base}"
  resource_group_name          = azurerm_resource_group.this.name
  container_app_environment_id = azurerm_container_app_environment.this.id
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  dynamic "registry" {
    for_each = var.registry_server == "" ? [] : [var.registry_server]
    content {
      server   = registry.value
      identity = azurerm_user_assigned_identity.app.id
    }
  }

  dynamic "secret" {
    for_each = module.core.secret_env_refs
    content {
      name                = local.secret_names[secret.key]
      identity            = azurerm_user_assigned_identity.app.id
      key_vault_secret_id = secret.value
    }
  }

  secret {
    name                = "ales-tokens"
    identity            = azurerm_user_assigned_identity.app.id
    key_vault_secret_id = module.core.tokens_secret_ref
  }

  ingress {
    external_enabled           = var.public_ingress
    target_port                = module.core.container_port
    transport                  = "auto"
    allow_insecure_connections = false

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = module.core.replica_count
    max_replicas = max(var.max_replicas, module.core.replica_count)

    container {
      name   = "ales-invariant"
      image  = module.core.image
      cpu    = var.cpu
      memory = var.memory

      dynamic "env" {
        for_each = module.core.plain_env
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = module.core.secret_env_refs
        content {
          name        = env.key
          secret_name = local.secret_names[env.key]
        }
      }

      env {
        name        = "ALES_TOKENS"
        secret_name = "ales-tokens"
      }

      startup_probe {
        transport               = "HTTP"
        port                    = module.core.container_port
        path                    = module.core.health_paths.liveness
        interval_seconds        = 5
        failure_count_threshold = 30
      }

      liveness_probe {
        transport               = "HTTP"
        port                    = module.core.container_port
        path                    = module.core.health_paths.liveness
        interval_seconds        = 10
        failure_count_threshold = 3
      }

      readiness_probe {
        transport               = "HTTP"
        port                    = module.core.container_port
        path                    = module.core.health_paths.readiness
        interval_seconds        = 5
        failure_count_threshold = 3
      }
    }

    http_scale_rule {
      name                = "http"
      concurrent_requests = "50"
    }
  }

  depends_on = [
    azurerm_role_assignment.app_database_url,
    azurerm_role_assignment.app_snapshot_key,
    azurerm_role_assignment.app_tokens,
    azurerm_postgresql_flexible_server_database.this,
  ]
}
