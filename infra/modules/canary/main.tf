# The synthetic monitor (Architecture.md, "Synthetic monitoring"): a
# CloudWatch Synthetics canary that signs in to a dedicated test client
# every 5 minutes, end to end (canary.js), and an alarm when it fails.
#
# Its configuration, including the test user's password, is a Secrets
# Manager secret that Terraform creates empty and never reads, so the
# password stays out of Terraform state. To set it up:
#
#   1. Create a public test client on a login host, with redirect URI
#      http://127.0.0.1/callback and post-logout redirect URI
#      http://127.0.0.1/logged-out (the canary never follows them), and a
#      test user in its pool.
#   2. Put the configuration in the secret (see the secret_arn output):
#      {"issuer": "https://<host>", "client_id": "...",
#       "redirect_uri": "http://127.0.0.1/callback",
#       "post_logout_redirect_uri": "http://127.0.0.1/logged-out",
#       "email": "...", "password": "..."}
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
  description = "Run the canary. Leave false until its secret holds the configuration."
  type        = bool
  default     = false
}

variable "schedule" {
  description = "How often the canary runs."
  type        = string
  default     = "rate(5 minutes)"
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
}

# ---- Configuration ----

resource "aws_secretsmanager_secret" "config" {
  name        = "${var.name_prefix}/canary"
  description = "Configuration of the ${local.name} canary: issuer, test client and test user (see infra/modules/canary)."
}

# ---- Artifacts ----

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${var.name_prefix}-canary-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = 30
    }
  }
}

# ---- Role ----

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "canary" {
  statement {
    actions   = ["s3:PutObject", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
  }
  statement {
    actions   = ["s3:ListAllMyBuckets"]
    resources = ["*"]
  }
  statement {
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/cwsyn-*"]
  }
  statement {
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["CloudWatchSynthetics"]
    }
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.config.arn]
  }
}

resource "aws_iam_role" "canary" {
  name               = "${local.name}-canary"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "canary" {
  role   = aws_iam_role.canary.id
  policy = data.aws_iam_policy_document.canary.json
}

# ---- Canary ----

data "archive_file" "canary" {
  type        = "zip"
  output_path = "${path.module}/.build/canary.zip"
  source {
    content  = file("${path.module}/canary.js")
    filename = "nodejs/node_modules/canary.js"
  }
}

resource "aws_synthetics_canary" "flow" {
  name                 = local.name
  artifact_s3_location = "s3://${aws_s3_bucket.artifacts.id}/"
  execution_role_arn   = aws_iam_role.canary.arn
  runtime_version      = "syn-nodejs-5.4"
  handler              = "canary.handler"
  zip_file             = data.archive_file.canary.output_path
  start_canary         = var.start

  success_retention_period = 7
  failure_retention_period = 30

  schedule {
    expression = var.schedule
  }

  run_config {
    timeout_in_seconds = 60
    environment_variables = {
      CANARY_SECRET_ARN = aws_secretsmanager_secret.config.arn
    }
  }

  depends_on = [aws_iam_role_policy.canary]
}

# Two failed runs in a row: one can be a blip.
resource "aws_cloudwatch_metric_alarm" "failing" {
  count = var.start ? 1 : 0

  alarm_name          = "${local.name}-failing"
  alarm_description   = "The ${local.name} canary can't sign in end to end. Its artifacts and logs say which step failed."
  namespace           = "CloudWatchSynthetics"
  metric_name         = "SuccessPercent"
  dimensions          = { CanaryName = aws_synthetics_canary.flow.name }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 100
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}

output "secret_arn" {
  description = "The canary's configuration secret."
  value       = aws_secretsmanager_secret.config.arn
}

output "canary_name" {
  value = aws_synthetics_canary.flow.name
}
