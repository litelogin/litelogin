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
}

module "worker" {
  source      = "../lambda"
  name        = "${var.name_prefix}-worker"
  zip_path    = var.zip_path
  policy_json = data.aws_iam_policy_document.worker.json
  memory_size = 256
  timeout     = local.worker_timeout

  environment = {
    LITELOGIN_CONFIG_TABLE           = var.config_table_name
    LITELOGIN_SESSION_TABLE          = var.session_table_name
    LITELOGIN_CONTINUATION_QUEUE_URL = aws_sqs_queue.continuation.url
  }
}

# ---- Triggers ----

# Only the changes that start a job invoke the Worker: for now, a user
# item modified (the Worker checks whether auth_version increased) or
# removed.
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
    filter {
      pattern = jsonencode({
        eventName = ["MODIFY", "REMOVE"]
        dynamodb = {
          Keys = {
            PK = { S = [{ prefix = "USER#" }] }
            SK = { S = ["DETAILS"] }
          }
        }
      })
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
