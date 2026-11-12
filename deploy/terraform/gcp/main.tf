resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
}

resource "random_password" "db" {
  length  = 32
  special = false # keeps the connection URL simple; entropy comes from length
}

locals {
  base   = "${var.name_prefix}-${var.environment}"
  suffix = random_string.suffix.result

  labels = merge(var.labels, {
    application = "ales-invariant"
    environment = var.environment
    managed-by  = "terraform"
  })

  db_name = "invariant"
  db_user = "alesapp"

  secret_ids = {
    database_url = "${local.base}-database-url"
    snapshot_key = "${local.base}-snapshot-key"
    tokens       = "${local.base}-tokens"
  }

  # Env var name -> Secret Manager secret_id, derived from the neutral contract.
  secret_env = {
    DATABASE_URL      = google_secret_manager_secret.this["database_url"].secret_id
    ALES_SNAPSHOT_KEY = google_secret_manager_secret.this["snapshot_key"].secret_id
    ALES_TOKENS       = google_secret_manager_secret.this["tokens"].secret_id
  }
}

# ------------------------------------------------------------------------------------------ APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "secretmanager.googleapis.com",
    "vpcaccess.googleapis.com",
    "compute.googleapis.com",
    "servicenetworking.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# ------------------------------------------------------------------------------------------ network
resource "google_compute_network" "this" {
  name                    = "vpc-${local.base}"
  auto_create_subnetworks = false

  depends_on = [google_project_service.apis]
}

resource "google_compute_global_address" "private_services" {
  name          = "psa-${local.base}"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.this.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.this.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
}

resource "google_vpc_access_connector" "this" {
  name          = substr("${local.base}-vpc", 0, 25)
  region        = var.region
  network       = google_compute_network.this.name
  ip_cidr_range = var.connector_cidr
  min_instances = 2
  max_instances = 3

  depends_on = [google_project_service.apis]
}

# ------------------------------------------------------------------------------------------ database (private IP only)
resource "google_sql_database_instance" "this" {
  name                = "${local.base}-pg-${local.suffix}"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = var.deletion_protection

  settings {
    tier              = var.sql_tier
    disk_size         = var.sql_disk_size_gb
    disk_autoresize   = true
    availability_type = var.sql_high_availability ? "REGIONAL" : "ZONAL"
    user_labels       = local.labels

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.this.id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true

      backup_retention_settings {
        retained_backups = var.sql_backup_retained_count
      }
    }
  }

  depends_on = [google_service_networking_connection.private_services]
}

resource "google_sql_database" "this" {
  name     = local.db_name
  instance = google_sql_database_instance.this.name
}

resource "google_sql_user" "app" {
  name     = local.db_user
  instance = google_sql_database_instance.this.name
  password = random_password.db.result
}

# ------------------------------------------------------------------------------------------ secrets
resource "google_secret_manager_secret" "this" {
  for_each  = local.secret_ids
  secret_id = each.value
  labels    = local.labels

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "database_url" {
  secret = google_secret_manager_secret.this["database_url"].id
  secret_data = format(
    "postgresql+psycopg://%s:%s@%s:5432/%s?sslmode=require",
    local.db_user,
    urlencode(random_password.db.result),
    google_sql_database_instance.this.private_ip_address,
    local.db_name,
  )
}

resource "google_secret_manager_secret_version" "snapshot_key" {
  secret      = google_secret_manager_secret.this["snapshot_key"].id
  secret_data = var.snapshot_key
}

resource "google_secret_manager_secret_version" "tokens" {
  secret      = google_secret_manager_secret.this["tokens"].id
  secret_data = var.tokens_json
}

# ------------------------------------------------------------------------------------------ identity (least privilege)
resource "google_service_account" "app" {
  account_id   = substr("${local.base}-run", 0, 30)
  display_name = "ALES INVARIANT Cloud Run runtime (${var.environment})"

  depends_on = [google_project_service.apis]
}

# Per-secret accessor grants; the runtime SA has no project-level roles.
resource "google_secret_manager_secret_iam_member" "app" {
  for_each  = google_secret_manager_secret.this
  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.app.email}"
}

# ------------------------------------------------------------------------------------------ neutral core contract
module "core" {
  source = "../modules/core"

  name                    = local.base
  image                   = var.image
  replica_count           = max(var.min_instances, 1)
  database_url_secret_ref = google_secret_manager_secret.this["database_url"].id
  tokens_secret_ref       = google_secret_manager_secret.this["tokens"].id
  snapshot_key_secret_ref = google_secret_manager_secret.this["snapshot_key"].id
  require_signatures      = var.require_signatures
  snapshot_lease_seconds  = var.snapshot_lease_seconds
  outbox_interval_seconds = var.outbox_interval_seconds
  max_body_bytes          = var.max_body_bytes
  snapshot_key_id         = var.snapshot_key_id
  tags                    = local.labels
}

# ------------------------------------------------------------------------------------------ compute
resource "google_cloud_run_v2_service" "this" {
  name                = local.base
  location            = var.region
  ingress             = var.ingress
  deletion_protection = var.deletion_protection
  labels              = local.labels

  template {
    service_account                  = google_service_account.app.email
    max_instance_request_concurrency = 80

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = max(var.max_instances, var.min_instances)
    }

    vpc_access {
      connector = google_vpc_access_connector.this.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = module.core.image

      ports {
        container_port = module.core.container_port
      }

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
      }

      dynamic "env" {
        for_each = module.core.plain_env
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = local.secret_env
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }

      # Startup uses readiness: no traffic until the database answers and the schema is at head.
      startup_probe {
        initial_delay_seconds = 5
        period_seconds        = 5
        timeout_seconds       = 3
        failure_threshold     = 30

        http_get {
          path = module.core.health_paths.readiness
          port = module.core.container_port
        }
      }

      liveness_probe {
        period_seconds    = 10
        timeout_seconds   = 3
        failure_threshold = 3

        http_get {
          path = module.core.health_paths.liveness
          port = module.core.container_port
        }
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.app,
    google_secret_manager_secret_version.database_url,
    google_secret_manager_secret_version.snapshot_key,
    google_secret_manager_secret_version.tokens,
    google_sql_database.this,
    google_sql_user.app,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "invokers" {
  for_each = toset(var.invoker_members)
  project  = google_cloud_run_v2_service.this.project
  location = google_cloud_run_v2_service.this.location
  name     = google_cloud_run_v2_service.this.name
  role     = "roles/run.invoker"
  member   = each.value
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  count    = var.allow_unauthenticated_invoker ? 1 : 0
  project  = google_cloud_run_v2_service.this.project
  location = google_cloud_run_v2_service.this.location
  name     = google_cloud_run_v2_service.this.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
