# Token signing keys: the key rotation Lambda, its daily schedule, and the
# IAM policy that lets other functions sign with the keys.
#
# The keys themselves are created at runtime by the rotation Lambda (see
# "Rotate signing keys" in Datamodel.md), so their ARNs aren't known here.
# Permissions are scoped by the tags the Lambda puts on every key instead:
# litelogin-purpose=token-signing and litelogin-environment=<environment>.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "system_log_level" {
  description = "Lambda's platform log level: INFO logs every invocation's platform lines; WARN only failed invocations' (Cost.md, \"Reduced monitoring\")."
  type        = string
  default     = "INFO"
}

variable "name_prefix" {
  description = "Prefix for resource names, e.g. litelogin-dev."
  type        = string
}

variable "environment" {
  description = "Environment name, tagged on the signing keys."
  type        = string
}

variable "zip_path" {
  description = "Path to the rotate Lambda package."
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

variable "session_table_name" {
  type = string
}

variable "table_kms_key_arn" {
  description = "Customer managed key encrypting the tables."
  type        = string
}

variable "schedule_expression" {
  description = "How often the rotation Lambda checks whether a step is due."
  type        = string
  default     = "rate(1 day)"
}

locals {
  tag_purpose     = "litelogin-purpose"
  tag_environment = "litelogin-environment"
  purpose         = "token-signing"
}

data "aws_region" "current" {}

# ---- Rotation Lambda ----

data "aws_iam_policy_document" "rotate" {
  # Only KEYS items in the Config table.
  statement {
    actions = [
      "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem",
      "dynamodb:Query", "dynamodb:ConditionCheckItem",
    ]
    resources = [var.config_table_arn]
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "dynamodb:LeadingKeys"
      values   = ["KEYS"]
    }
  }

  # Reading and writing an encrypted table uses its KMS key through DynamoDB.
  statement {
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = [var.table_kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["dynamodb.${data.aws_region.current.region}.amazonaws.com"]
    }
  }

  # Create only RSA signing keys, and only with this environment's tags.
  statement {
    actions   = ["kms:CreateKey", "kms:TagResource"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/${local.tag_purpose}"
      values   = [local.purpose]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/${local.tag_environment}"
      values   = [var.environment]
    }
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = [local.tag_purpose, local.tag_environment]
    }
  }
  statement {
    actions   = ["kms:CreateKey"]
    resources = ["*"]
    effect    = "Deny"
    condition {
      test     = "StringNotEquals"
      variable = "kms:KeySpec"
      values   = ["RSA_2048"]
    }
  }
  statement {
    actions   = ["kms:CreateKey"]
    resources = ["*"]
    effect    = "Deny"
    condition {
      test     = "StringNotEquals"
      variable = "kms:KeyUsage"
      values   = ["SIGN_VERIFY"]
    }
  }

  # Manage only keys tagged as this environment's signing keys.
  statement {
    actions   = ["kms:GetPublicKey", "kms:ScheduleKeyDeletion", "kms:DescribeKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.tag_purpose}"
      values   = [local.purpose]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.tag_environment}"
      values   = [var.environment]
    }
  }
}

module "rotate" {
  source       = "../lambda"
  name         = "${var.name_prefix}-rotate"
  zip_path     = var.zip_path
  code_signing = var.code_signing
  policy_json  = data.aws_iam_policy_document.rotate.json
  memory_size  = 256
  timeout      = 60

  system_log_level = var.system_log_level

  environment = {
    LITELOGIN_CONFIG_TABLE  = var.config_table_name
    LITELOGIN_SESSION_TABLE = var.session_table_name
    LITELOGIN_ENVIRONMENT   = var.environment
  }
}

# ---- Schedule ----

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.name_prefix}-rotate-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

resource "aws_iam_role_policy" "scheduler" {
  name = "invoke-rotate"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = module.rotate.function_arn
    }]
  })
}

resource "aws_scheduler_schedule" "rotate" {
  name                = "${var.name_prefix}-rotate"
  schedule_expression = var.schedule_expression

  flexible_time_window {
    mode                      = "FLEXIBLE"
    maximum_window_in_minutes = 60
  }

  target {
    arn      = module.rotate.function_arn
    role_arn = aws_iam_role.scheduler.arn
    input    = "{}"

    retry_policy {
      maximum_retry_attempts       = 3
      maximum_event_age_in_seconds = 3600
    }
  }
}

# ---- Signing permission for other functions ----

data "aws_iam_policy_document" "sign" {
  statement {
    actions   = ["kms:Sign"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.tag_purpose}"
      values   = [local.purpose]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.tag_environment}"
      values   = [var.environment]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:SigningAlgorithm"
      values   = ["RSASSA_PKCS1_V1_5_SHA_256"]
    }
  }
}

output "sign_policy_json" {
  description = "IAM policy statements allowing kms:Sign with this environment's signing keys."
  value       = data.aws_iam_policy_document.sign.json
}

output "rotate_function_name" {
  value = module.rotate.function_name
}
