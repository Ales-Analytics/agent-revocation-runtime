output "service_url" {
  description = "Cloud Run service URL (reachability depends on ingress and invoker settings)."
  value       = google_cloud_run_v2_service.this.uri
}

output "service_name" {
  description = "Cloud Run service name."
  value       = google_cloud_run_v2_service.this.name
}

output "runtime_service_account" {
  description = "Runtime service account email (grant it nothing else)."
  value       = google_service_account.app.email
}

output "secret_ids" {
  description = "Secret Manager secret IDs (references only)."
  value       = local.secret_ids
}

output "cloud_sql_private_ip" {
  description = "Private IP of the Cloud SQL instance."
  value       = google_sql_database_instance.this.private_ip_address
}

output "vpc_connector" {
  description = "Serverless VPC Access connector ID."
  value       = google_vpc_access_connector.this.id
}
