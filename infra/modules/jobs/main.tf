# Background jobs: the Worker Lambda, the Config table stream that starts
# its jobs, the SQS continuation queue that carries a long job across
# invocations, and their dead-letter queues and alarms (Architecture.md,
# "Background jobs").

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "name_prefix" {
  description = "Prefix for resource names, e.g. litelogin-dev."
  type        = string
}

variable "zip_path" {
  description = "Path to the worker Lambda package."
  type        = string
}

variable "code_signing" {
  description = "The codesigning module's code_signing output; null to deploy unsigned."
  type = object({
    bucket       = string
    profile_name = string
    config_arn   = string
  })
  default = null
}

variable "config_table_name" {
  type = string
}

variable "config_table_arn" {
  type = string
}

variable "config_stream_arn" {
  type = string
}

variable "session_table_name" {
  type = string
}

variable "session_table_arn" {
  type = string
}

variable "table_kms_key_arn" {
  description = "Customer managed key encrypting the tables and their streams."
  type        = string
}

variable "custom_hosts" {
  description = "The multi-tenant distribution and connection group serving custom hosts (from the edge module). Null: no custom hosts."
  type = object({
    distribution_id      = string
    distribution_arn     = string
    connection_group_id  = string
    connection_group_arn = string
    routing_endpoint     = string
  })
  default = null
}

variable "system_log_level" {
  description = "Lambda's platform log level: INFO logs every invocation's platform lines; WARN only failed invocations' (Cost.md, \"Reduced monitoring\")."
  type        = string
  default     = "INFO"
}

variable "reduced_metrics" {
  description = "Publish only the metrics alarms use; the rest become log fields (Cost.md, \"Reduced monitoring\")."
  type        = bool
  default     = false
}

variable "reconcile_schedule" {
  description = "How often the reconciler retries stalled custom host and pool deletion work."
  type        = string
  default     = "rate(5 minutes)"
}

variable "alarm_actions" {
  description = "ARNs (e.g. SNS topics) notified when a dead-letter queue receives a message."
  type        = list(string)
  default     = []
}

locals {
  # SQS hides a message for this long while the Worker processes it. AWS
  # recommends at least six times the function timeout.
  worker_timeout     = 60
  visibility_timeout = 6 * local.worker_timeout
  max_receive_count  = 5
  dlq_retention      = 1209600 # 14 days, the maximum
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

# ---- Queues ----

resource "aws_sqs_queue" "continuation_dlq" {
  name                      = "${var.name_prefix}-jobs-dlq"
  message_retention_seconds = local.dlq_retention
  sqs_managed_sse_enabled   = true
}

# A job that runs out of time puts the rest of its work here, and the
# Worker carries on from it. A message that keeps failing moves to the
# dead-letter queue.
resource "aws_sqs_queue" "continuation" {
  name                       = "${var.name_prefix}-jobs"
  visibility_timeout_seconds = local.visibility_timeout
  sqs_managed_sse_enabled    = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.continuation_dlq.arn
    maxReceiveCount     = local.max_receive_count
  })
}

# Stream records the Worker failed on after every retry. A record can't be
# re-driven from here into the stream: the message describes the records,
# for investigation.
resource "aws_sqs_queue" "stream_dlq" {
  name                      = "${var.name_prefix}-stream-dlq"
  message_retention_seconds = local.dlq_retention
  sqs_managed_sse_enabled   = true
}

# ---- Worker Lambda ----

data "aws_iam_policy_document" "worker" {
  # Revocation cleanup: read the user, list its credentials from Session
  # GSI1 and delete them.
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.config_table_arn]
  }
  statement {
    actions   = ["dynamodb:Query"]
    resources = ["${var.session_table_arn}/index/GSI1"]
  }
  statement {
    actions   = ["dynamodb:BatchWriteItem"]
    resources = [var.session_table_arn]
  }
  # A deleted user's passkeys (USER#{user} / PASSKEY#*), found with Query.
  statement {
    actions   = ["dynamodb:BatchWriteItem"]
    resources = [var.config_table_arn]
  }

  # Custom hosts and pool deletion: hosts, pools and their org index items,
  # outstanding work (GSI2), a pool's users (GSI1) and their memberships.
  statement {
    actions = [
      "dynamodb:Query", "dynamodb:BatchGetItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem",
      "dynamodb:ConditionCheckItem",
    ]
    resources = [var.config_table_arn, "${var.config_table_arn}/index/*"]
  }

  # Reading the Config table stream (by the event source mapping, with the
  # function's role).
  statement {
    actions   = ["dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator"]
    resources = [var.config_stream_arn]
  }
  statement {
    actions   = ["dynamodb:ListStreams"]
    resources = ["*"]
  }

  # The tables and their stream are encrypted with the customer managed key.
  statement {
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = [var.table_kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["dynamodb.${data.aws_region.current.region}.amazonaws.com"]
    }
  }
  # Lambda reads the stream for the function, outside a DynamoDB call.
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.table_kms_key_arn]
  }

  statement {
    actions   = ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
    resources = [aws_sqs_queue.continuation.arn]
  }
  # The stream mapping's failure destination.
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.stream_dlq.arn]
  }

  # Custom hosts: tenants of the multi-tenant distribution, with
  # CloudFront-managed certificates (which CloudFront requests from ACM
  # with the caller's permissions). CloudFront leaves a deleted tenant's
  # certificate behind, so the Worker lists and deletes it.
  dynamic "statement" {
    for_each = var.custom_hosts == null ? [] : [var.custom_hosts]
    content {
      actions = [
        "cloudfront:CreateDistributionTenant", "cloudfront:UpdateDistributionTenant",
        "cloudfront:DeleteDistributionTenant",
      ]
      resources = [
        statement.value.distribution_arn, statement.value.connection_group_arn,
        "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution-tenant/*",
      ]
    }
  }
  dynamic "statement" {
    for_each = var.custom_hosts == null ? [] : [var.custom_hosts]
    content {
      actions = [
        "cloudfront:GetDistributionTenant", "cloudfront:GetDistributionTenantByDomain",
        "cloudfront:GetManagedCertificateDetails", "cloudfront:GetConnectionGroup",
        "acm:RequestCertificate", "acm:DescribeCertificate", "acm:DeleteCertificate", "acm:ListCertificates",
      ]
      resources = ["*"]
    }
  }
}

module "worker" {
  source       = "../lambda"
  name         = "${var.name_prefix}-worker"
  zip_path     = var.zip_path
  code_signing = var.code_signing
  policy_json  = data.aws_iam_policy_document.worker.json
  memory_size  = 256
  timeout      = local.worker_timeout

  system_log_level = var.system_log_level

  environment = merge({
    LITELOGIN_CONFIG_TABLE           = var.config_table_name
    LITELOGIN_SESSION_TABLE          = var.session_table_name
    LITELOGIN_CONTINUATION_QUEUE_URL = aws_sqs_queue.continuation.url
    LITELOGIN_TENANT_DISTRIBUTION_ID = try(var.custom_hosts.distribution_id, "")
    LITELOGIN_CONNECTION_GROUP_ID    = try(var.custom_hosts.connection_group_id, "")
    LITELOGIN_ROUTING_ENDPOINT       = try(var.custom_hosts.routing_endpoint, "")
  }, var.reduced_metrics ? { LITELOGIN_METRICS = "reduced" } : {})
}

# ---- Triggers ----

# Only the changes that might start a job invoke the Worker (it checks
# each record further): a user modified (auth_version increased?) or
# removed; a login host created or modified (pending, removing?); a pool
# modified (deleting?).
resource "aws_lambda_event_source_mapping" "stream" {
  function_name     = module.worker.function_arn
  event_source_arn  = var.config_stream_arn
  starting_position = "LATEST"
  batch_size        = 100

  maximum_batching_window_in_seconds = 1
  bisect_batch_on_function_error     = true
  maximum_retry_attempts             = 5
  maximum_record_age_in_seconds      = 3600
  function_response_types            = ["ReportBatchItemFailures"]

  filter_criteria {
    dynamic "filter" {
      for_each = {
        "USER#"       = ["MODIFY", "REMOVE"]
        "LOGIN_HOST#" = ["INSERT", "MODIFY"]
        "POOL#"       = ["MODIFY"]
      }
      content {
        pattern = jsonencode({
          eventName = filter.value
          dynamodb = {
            Keys = {
              PK = { S = [{ prefix = filter.key }] }
              SK = { S = ["DETAILS"] }
            }
          }
        })
      }
    }
  }

  destination_config {
    on_failure {
      destination_arn = aws_sqs_queue.stream_dlq.arn
    }
  }

  depends_on = [module.worker]
}

resource "aws_lambda_event_source_mapping" "continuation" {
  function_name           = module.worker.function_arn
  event_source_arn        = aws_sqs_queue.continuation.arn
  batch_size              = 10
  function_response_types = ["ReportBatchItemFailures"]
}

# The reconciler: retries custom host and pool deletion work that hasn't
# progressed (a host waiting for DNS, a tenant being disabled).
resource "aws_scheduler_schedule" "reconcile" {
  name                = "${var.name_prefix}-reconcile"
  schedule_expression = var.reconcile_schedule
  flexible_time_window {
    mode = "OFF"
  }
  target {
    arn      = module.worker.function_arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ type = "reconcile" })
    retry_policy {
      maximum_retry_attempts = 0 # the next run retries
    }
  }
}

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.name_prefix}-reconcile-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

resource "aws_iam_role_policy" "scheduler" {
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "lambda:InvokeFunction", Resource = module.worker.function_arn }]
  })
}

# ---- Alarms ----

resource "aws_cloudwatch_metric_alarm" "dlq" {
  for_each = {
    jobs   = aws_sqs_queue.continuation_dlq.name
    stream = aws_sqs_queue.stream_dlq.name
  }

  alarm_name          = "${each.value}-not-empty"
  alarm_description   = "A background job failed after every retry. Its message is in ${each.value}."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = each.value }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}

output "worker_function_name" {
  value = module.worker.function_name
}

output "continuation_queue_url" {
  value = aws_sqs_queue.continuation.url
}

output "dlq_names" {
  value = [aws_sqs_queue.continuation_dlq.name, aws_sqs_queue.stream_dlq.name]
}
