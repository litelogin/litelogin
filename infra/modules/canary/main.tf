# The synthetic monitor (Architecture.md, "Synthetic monitoring"): a
# Lambda function (canary.js, Node.js) that EventBridge Scheduler runs
# every 5 minutes. It signs in to a dedicated test client end to end, and
# an alarm fires when it fails twice in a row.
#
# It's a plain Lambda function rather than a CloudWatch Synthetics canary:
# it makes HTTP requests only, so it needs nothing Synthetics adds, and
# Synthetics' per-run price was most of its cost (Cost.md).
#
# Its configuration, including the test user's password, is an SSM
# SecureString parameter that Terraform doesn't manage, so the password
# stays out of Terraform state. To set it up:
#
#   1. Create a public test client on a login host, with redirect URI
#      http://127.0.0.1/callback and post-logout redirect URI
#      http://127.0.0.1/logged-out (the canary never follows them), and a
#      test user in its pool.
#   2. Create the parameter (see the parameter_name output):
#      aws ssm put-parameter --type SecureString --name <parameter_name> \
#        --value '{"issuer": "https://<host>", "client_id": "...",
#          "redirect_uri": "http://127.0.0.1/callback",
#          "post_logout_redirect_uri": "http://127.0.0.1/logged-out",
#          "email": "...", "password": "..."}'
#   3. Set start = true and apply.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}

variable "name_prefix" {
  type = string
}

variable "start" {
  description = "Run the canary. Leave false until its parameter holds the configuration."
  type        = bool
  default     = false
}

variable "schedule" {
  description = "How often the canary runs."
  type        = string
  default     = "rate(5 minutes)"
}

variable "code_signing" {
  description = "The codesigning module's code_signing output, or null to deploy unsigned."
  type = object({
    bucket       = string
    profile_name = string
    config_arn   = string
  })
  default = null
}

variable "alarm_actions" {
  description = "ARNs notified when the canary fails."
  type        = list(string)
  default     = []
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name = "${var.name_prefix}-flow"
  # Encrypted with the account's AWS managed key for SSM (aws/ssm), whose
  # key policy lets the account's principals decrypt through SSM.
  parameter_name = "/${var.name_prefix}/canary"
  parameter_arn  = "arn:aws:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${local.parameter_name}"
}

# ---- Function ----

data "archive_file" "canary" {
  type        = "zip"
  output_path = "${path.module}/.build/canary.zip"
  source {
    content  = file("${path.module}/canary.js")
    filename = "canary.js"
  }
}

data "aws_iam_policy_document" "canary" {
  statement {
    actions   = ["ssm:GetParameter"]
    resources = [local.parameter_arn]
  }
}

module "function" {
  source       = "../lambda"
  name         = local.name
  zip_path     = data.archive_file.canary.output_path
  runtime      = "nodejs24.x"
  handler      = "canary.handler"
  code_signing = var.code_signing
  policy_json  = data.aws_iam_policy_document.canary.json
  memory_size  = 256
  timeout      = 60

  environment = {
    CANARY_PARAMETER = local.parameter_name
  }
}

# A failed run isn't retried: the next one is 5 minutes later, and the
# alarm counts runs.
resource "aws_lambda_function_event_invoke_config" "canary" {
  function_name          = module.function.function_name
  maximum_retry_attempts = 0
}

# ---- Schedule ----

resource "aws_scheduler_schedule" "canary" {
  name                = local.name
  schedule_expression = var.schedule
  state               = var.start ? "ENABLED" : "DISABLED"
  flexible_time_window {
    mode = "OFF"
  }
  target {
    arn      = module.function.function_arn
    role_arn = aws_iam_role.scheduler.arn
    retry_policy {
      maximum_retry_attempts = 0
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
  name               = "${local.name}-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

data "aws_iam_policy_document" "scheduler" {
  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = [module.function.function_arn]
  }
}

resource "aws_iam_role_policy" "scheduler" {
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler.json
}

# ---- Alarm ----

# Two failed runs in a row: one can be a blip. Lambda's Errors metric has a
# datapoint for every run (0 when it succeeds), so no data means the
# canary isn't running, which counts as failing.
resource "aws_cloudwatch_metric_alarm" "failing" {
  count = var.start ? 1 : 0

  alarm_name          = "${local.name}-failing"
  alarm_description   = "The ${local.name} canary can't sign in end to end, or isn't running. Its log says which step failed."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = module.function.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}

output "parameter_name" {
  description = "The SSM parameter holding the canary's configuration."
  value       = local.parameter_name
}

output "function_name" {
  value = module.function.function_name
}
