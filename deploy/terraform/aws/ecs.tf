locals {
  # Secret refs to inject. ECS cannot mount secrets as files, so the token registry is injected as ALES_TOKENS.
  ecs_secrets = merge(
    module.core.secret_env_refs,
    { ALES_TOKENS = module.core.tokens_secret_ref },
  )
}

# ------------------------------------------------------------------------------------------ logs
resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${local.base}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
}

# ------------------------------------------------------------------------------------------ IAM
data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# Execution role: used by ECS to pull the image, write logs and resolve the three secrets. Nothing else.
resource "aws_iam_role" "execution" {
  name               = "${local.base}-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid       = "EcrPull"
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
    resources = ["arn:aws:ecr:${var.region}:${data.aws_caller_identity.current.account_id}:repository/*"]
  }

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.this.arn}:*"]
  }

  statement {
    sid     = "ReadOnlyTheThreeSecrets"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.database_url.arn,
      aws_secretsmanager_secret.snapshot_key.arn,
      aws_secretsmanager_secret.tokens.arn,
    ]
  }

  statement {
    sid       = "DecryptSecretsViaSecretsManagerOnly"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.this.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "least-privilege"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

# Task role: the application makes no AWS API calls, so it has NO permissions.
resource "aws_iam_role" "task" {
  name               = "${local.base}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

# ------------------------------------------------------------------------------------------ ALB
resource "aws_lb" "this" {
  name                       = substr(local.base, 0, 32)
  internal                   = var.alb_internal
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = var.alb_internal ? aws_subnet.private[*].id : aws_subnet.public[*].id
  drop_invalid_header_fields = true
  enable_deletion_protection = var.alb_deletion_protection
}

resource "aws_lb_target_group" "this" {
  name        = substr("${local.base}-tg", 0, 32)
  port        = module.core.container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.this.id

  deregistration_delay = 30

  health_check {
    path                = module.core.health_paths.readiness
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# ------------------------------------------------------------------------------------------ ECS
resource "aws_ecs_cluster" "this" {
  name = local.base

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = local.base
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([
    {
      name                   = "ales-invariant"
      image                  = module.core.image
      essential              = true
      user                   = "10001:10001"
      readonlyRootFilesystem = true
      portMappings           = [{ containerPort = module.core.container_port, protocol = "tcp" }]
      environment            = [for k, v in module.core.plain_env : { name = k, value = v }]
      secrets                = [for k, v in local.ecs_secrets : { name = k, valueFrom = v }]
      mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]
      linuxParameters        = { capabilities = { drop = ["ALL"] } }
      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:${module.core.container_port}${module.core.health_paths.liveness}', timeout=3).status == 200 else 1)\""]
        interval    = 15
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.this.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "ales"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "this" {
  name                               = local.base
  cluster                            = aws_ecs_cluster.this.id
  task_definition                    = aws_ecs_task_definition.this.arn
  desired_count                      = module.core.replica_count
  launch_type                        = "FARGATE"
  health_check_grace_period_seconds  = 60
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  enable_execute_command             = false
  propagate_tags                     = "SERVICE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "ales-invariant"
    container_port   = module.core.container_port
  }

  lifecycle {
    ignore_changes = [desired_count] # owned by autoscaling after creation
  }

  depends_on = [
    aws_lb_listener.https,
    aws_rds_cluster_instance.this,
    aws_secretsmanager_secret_version.database_url,
    aws_secretsmanager_secret_version.snapshot_key,
    aws_secretsmanager_secret_version.tokens,
    aws_iam_role_policy.execution,
  ]
}

resource "aws_appautoscaling_target" "this" {
  max_capacity       = max(var.max_replicas, module.core.replica_count)
  min_capacity       = module.core.replica_count
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.this.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${local.base}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.this.resource_id
  scalable_dimension = aws_appautoscaling_target.this.scalable_dimension
  service_namespace  = aws_appautoscaling_target.this.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = 70

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}
