output "alb_dns_name" {
  description = "ALB DNS name (point your DNS record / CNAME at it; DNS is out of scope)."
  value       = aws_lb.this.dns_name
}

output "cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.this.name
}

output "service_name" {
  description = "ECS service name."
  value       = aws_ecs_service.this.name
}

output "task_definition_arn" {
  description = "Task definition ARN (use for the one-off migration task)."
  value       = aws_ecs_task_definition.this.arn
}

output "private_subnet_ids" {
  description = "Private subnet IDs (for run-task)."
  value       = aws_subnet.private[*].id
}

output "service_security_group_id" {
  description = "Service security group ID (for run-task)."
  value       = aws_security_group.service.id
}

output "kms_key_arn" {
  description = "CMK used for secrets, logs and Aurora."
  value       = aws_kms_key.this.arn
}

output "secret_arns" {
  description = "Secrets Manager ARNs (references only)."
  value = {
    database_url = aws_secretsmanager_secret.database_url.arn
    snapshot_key = aws_secretsmanager_secret.snapshot_key.arn
    tokens       = aws_secretsmanager_secret.tokens.arn
  }
}

output "db_endpoint" {
  description = "Aurora writer endpoint (private)."
  value       = aws_rds_cluster.this.endpoint
}

output "log_group" {
  description = "CloudWatch log group."
  value       = aws_cloudwatch_log_group.this.name
}
