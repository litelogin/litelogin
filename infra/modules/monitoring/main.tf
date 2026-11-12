# Alarms and a dashboard for an environment (Architecture.md,
# "Observability"), and the SNS topic alarms notify.
#
# Application metrics come from the functions' embedded metric format log
# lines, in the LiteLogin namespace with a Service dimension (internal/
# metrics). An alarm must name a metric's exact dimensions, so a metric
# recorded with a Reason is alarmed on per reason, summed by metric math.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "name_prefix" {
  type = string
}

variable "function_names" {
  description = "The environment's Lambda functions, by role (auth, admin, worker, rotate)."
  type        = map(string)
}

variable "table_names" {
  description = "The environment's DynamoDB tables."
  type        = list(string)
}

variable "alarm_email" {
  description = "Address subscribed to the alarm topic (it must confirm the subscription). Empty: none."
  type        = string
  default     = ""
}

variable "refresh_reuse_threshold" {
  description = "Refresh token reuses in 5 minutes that count as a spike."
  type        = number
  default     = 20
}

variable "work_age_threshold" {
  description = "Age in seconds of the oldest outstanding background work that raises an alarm."
  type        = number
  default     = 3600
}

data "aws_region" "current" {}

locals {
  ns     = "LiteLogin"
  period = 300
}

# ---- Notifications ----

resource "aws_sns_topic" "alarms" {
  name              = "${var.name_prefix}-alarms"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# ---- Lambda ----

resource "aws_cloudwatch_metric_alarm" "lambda" {
  for_each = {
    for pair in setproduct(keys(var.function_names), ["Errors", "Throttles"]) : "${pair[0]}-${lower(pair[1])}" => {
      function = var.function_names[pair[0]]
      metric   = pair[1]
    }
  }

  alarm_name          = "${var.name_prefix}-${each.key}"
  alarm_description   = "${each.value.function} reported ${lower(each.value.metric)}."
  namespace           = "AWS/Lambda"
  metric_name         = each.value.metric
  dimensions          = { FunctionName = each.value.function }
  statistic           = "Sum"
  period              = local.period
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
}

# ---- DynamoDB ----

resource "aws_cloudwatch_metric_alarm" "dynamodb_throttles" {
  for_each = toset(var.table_names)

  alarm_name          = "${each.value}-throttles"
  alarm_description   = "Requests to ${each.value} were throttled."
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  metric_query {
    id          = "throttles"
    expression  = "reads + writes"
    label       = "Throttle events"
    return_data = true
  }
  dynamic "metric_query" {
    for_each = { reads = "ReadThrottleEvents", writes = "WriteThrottleEvents" }
    content {
      id = metric_query.key
      metric {
        namespace   = "AWS/DynamoDB"
        metric_name = metric_query.value
        dimensions  = { TableName = each.value }
        stat        = "Sum"
        period      = local.period
      }
    }
  }
}

# ---- Application metrics ----

resource "aws_cloudwatch_metric_alarm" "kms_sign" {
  alarm_name          = "${var.name_prefix}-kms-sign-failures"
  alarm_description   = "Token signing with KMS failed or was throttled. Throttling means the KMS Sign quota is too low for the load."
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  metric_query {
    id          = "failures"
    expression  = "throttled + errors"
    label       = "KMS Sign failures"
    return_data = true
  }
  dynamic "metric_query" {
    for_each = { throttled = "throttled", errors = "error" }
    content {
      id = metric_query.key
      metric {
        namespace   = local.ns
        metric_name = "KMSSignFailed"
        dimensions  = { Service = "auth", Reason = metric_query.value }
        stat        = "Sum"
        period      = local.period
      }
    }
  }
}

# The reconciler reports the age every run, so a missing value means it
# isn't running: that's an alarm too.
resource "aws_cloudwatch_metric_alarm" "work_age" {
  alarm_name          = "${var.name_prefix}-outstanding-work-age"
  alarm_description   = "Background work (a custom host or pool deletion) has been outstanding for over ${var.work_age_threshold / 60} minutes, or the reconciler isn't reporting. See work_last_error on the host or pool."
  namespace           = local.ns
  metric_name         = "OldestOutstandingWorkAge"
  dimensions          = { Service = "worker" }
  statistic           = "Maximum"
  period              = 900
  evaluation_periods  = 1
  threshold           = var.work_age_threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_metric_alarm" "refresh_reuse" {
  alarm_name          = "${var.name_prefix}-refresh-token-reuse"
  alarm_description   = "More than ${var.refresh_reuse_threshold} refresh tokens were reused in 5 minutes: possible token theft, or a client that doesn't store rotated tokens."
  namespace           = local.ns
  metric_name         = "RefreshTokenReuse"
  dimensions          = { Service = "auth" }
  statistic           = "Sum"
  period              = local.period
  evaluation_periods  = 1
  threshold           = var.refresh_reuse_threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
}

# ---- Dashboard ----

locals {
  region = data.aws_region.current.region

  widgets = [
    { title = "Logins", metrics = [
      [local.ns, "LoginSucceeded", "Service", "auth", { stat = "Sum", label = "Succeeded" }],
      [local.ns, "LoginFailed", "Service", "auth", "Reason", "bad_credentials", { stat = "Sum", label = "Wrong password or email" }],
      [local.ns, "LoginFailed", "Service", "auth", "Reason", "locked", { stat = "Sum", label = "Locked out" }],
      [local.ns, "Lockout", "Service", "auth", { stat = "Sum", label = "Lockouts" }],
    ] },
    { title = "Tokens", metrics = [
      [local.ns, "TokensIssued", "Service", "auth", "GrantType", "authorization_code", { stat = "Sum", label = "Code exchange" }],
      [local.ns, "TokensIssued", "Service", "auth", "GrantType", "refresh_token", { stat = "Sum", label = "Refresh" }],
      [local.ns, "TokenIssuanceFailed", "Service", "auth", "Reason", "invalid_grant", { stat = "Sum", label = "invalid_grant" }],
      [local.ns, "TokenIssuanceFailed", "Service", "auth", "Reason", "invalid_client", { stat = "Sum", label = "invalid_client" }],
      [local.ns, "TokenIssuanceFailed", "Service", "auth", "Reason", "server_error", { stat = "Sum", label = "server_error" }],
    ] },
    { title = "Latency (p50, p99)", metrics = [
      [local.ns, "TokenLatency", "Service", "auth", { stat = "p50", label = "/token p50" }],
      [local.ns, "TokenLatency", "Service", "auth", { stat = "p99", label = "/token p99" }],
      [local.ns, "KMSSignLatency", "Service", "auth", { stat = "p50", label = "KMS Sign p50" }],
      [local.ns, "KMSSignLatency", "Service", "auth", { stat = "p99", label = "KMS Sign p99" }],
      [local.ns, "PasswordVerifyLatency", "Service", "auth", { stat = "p50", label = "Password check p50" }],
      [local.ns, "PasswordVerifyLatency", "Service", "auth", { stat = "p99", label = "Password check p99" }],
    ] },
    { title = "Security events", metrics = [
      [local.ns, "RefreshTokenReuse", "Service", "auth", { stat = "Sum", label = "Refresh token reuse" }],
      [local.ns, "AuthorizationCodeReuse", "Service", "auth", { stat = "Sum", label = "Code reuse" }],
      [local.ns, "RefreshRotationFailed", "Service", "auth", "Reason", "condition", { stat = "Sum", label = "Rotation lost a race" }],
      [local.ns, "RefreshRotationFailed", "Service", "auth", "Reason", "error", { stat = "Sum", label = "Rotation error" }],
    ] },
    { title = "Failures", metrics = [
      [local.ns, "KMSSignFailed", "Service", "auth", "Reason", "throttled", { stat = "Sum", label = "KMS Sign throttled" }],
      [local.ns, "KMSSignFailed", "Service", "auth", "Reason", "error", { stat = "Sum", label = "KMS Sign error" }],
      [local.ns, "EmailSendFailed", "Service", "auth", { stat = "Sum", label = "Email (auth)" }],
      [local.ns, "EmailSendFailed", "Service", "admin", { stat = "Sum", label = "Email (admin)" }],
    ] },
    { title = "Background work", metrics = [
      [local.ns, "OldestOutstandingWorkAge", "Service", "worker", { stat = "Maximum", label = "Oldest outstanding work (s)" }],
      [local.ns, "CustomDomainOnboardingDuration", "Service", "worker", { stat = "Maximum", label = "Custom domain onboarding (s)" }],
    ] },
    # concat, not flatten: flatten would flatten the rows themselves.
    { title = "Lambda errors and throttles", metrics = concat(
      [for role, fn in var.function_names : ["AWS/Lambda", "Errors", "FunctionName", fn, { stat = "Sum", label = "${role} errors" }]],
      [for role, fn in var.function_names : ["AWS/Lambda", "Throttles", "FunctionName", fn, { stat = "Sum", label = "${role} throttles" }]],
    ) },
    { title = "Auth Lambda duration and concurrency", metrics = [
      ["AWS/Lambda", "Duration", "FunctionName", var.function_names["auth"], { stat = "p99", label = "Duration p99 (ms)" }],
      ["AWS/Lambda", "ConcurrentExecutions", "FunctionName", var.function_names["auth"], { stat = "Maximum", label = "Concurrency", yAxis = "right" }],
    ] },
  ]
}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = var.name_prefix
  dashboard_body = jsonencode({
    widgets = concat(
      [for i, w in local.widgets : {
        type   = "metric"
        x      = (i % 2) * 12
        y      = floor(i / 2) * 6
        width  = 12
        height = 6
        properties = {
          title   = w.title
          region  = local.region
          view    = "timeSeries"
          period  = local.period
          metrics = w.metrics
        }
      }],
      [{
        type   = "alarm"
        x      = 0
        y      = ceil(length(local.widgets) / 2) * 6
        width  = 24
        height = 6
        properties = {
          title = "Alarms"
          alarms = concat(
            [for a in aws_cloudwatch_metric_alarm.lambda : a.arn],
            [for a in aws_cloudwatch_metric_alarm.dynamodb_throttles : a.arn],
            [aws_cloudwatch_metric_alarm.kms_sign.arn, aws_cloudwatch_metric_alarm.work_age.arn, aws_cloudwatch_metric_alarm.refresh_reuse.arn],
          )
        }
      }],
    )
  })
}

output "alarm_topic_arn" {
  description = "SNS topic every alarm notifies; pass to other modules' alarm_actions."
  value       = aws_sns_topic.alarms.arn
}

output "dashboard_name" {
  value = aws_cloudwatch_dashboard.this.dashboard_name
}
