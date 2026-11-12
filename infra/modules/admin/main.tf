# The Admin API: the Admin Lambda behind its own function URL with AWS_IAM
# auth (Architecture.md, "Admin API"), and the KMS HMAC key that signs its
# pagination cursors.
#
# Access is granted in IAM: any principal in this account whose identity
# policy allows lambda:InvokeFunctionUrl on the function can call it. It
# manages every org, so grant it only to deployment operators and the
# management tools that act for them.

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
  description = "Path to the admin Lambda package."
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

variable "session_table_arn" {
  type = string
}

variable "table_kms_key_arn" {
  description = "Customer managed key encrypting the tables."
  type        = string
}

variable "default_host_domain" {
  description = "Parent domain of default login hosts: a client's default host is {label}.{domain}."
  type        = string
}

variable "custom_host_target" {
  description = "Where custom hosts' CNAME records point (the connection group's routing endpoint). Empty: custom hosts aren't supported."
  type        = string
  default     = ""
}

variable "email_from" {
  description = "Sender address of user invites."
  type        = string
}

variable "ses_configuration_set_name" {
  type = string
}

variable "ses_configuration_set_arn" {
  type = string
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# ---- Cursor key ----

# An HMAC key in KMS: the key material never leaves KMS, so neither the
# Lambda nor Terraform holds a secret.
resource "aws_kms_key" "cursor" {
  description              = "${var.name_prefix}: signs the Admin API's pagination cursors"
  key_usage                = "GENERATE_VERIFY_MAC"
  customer_master_key_spec = "HMAC_256"
  deletion_window_in_days  = 7
}

resource "aws_kms_alias" "cursor" {
  name          = "alias/${var.name_prefix}-admin-cursor"
  target_key_id = aws_kms_key.cursor.key_id
}

# ---- Lambda ----

data "aws_iam_policy_document" "admin" {
  statement {
    actions = [
      "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem",
      "dynamodb:Query", "dynamodb:BatchGetItem", "dynamodb:BatchWriteItem", "dynamodb:ConditionCheckItem",
    ]
    resources = [
      var.config_table_arn, "${var.config_table_arn}/index/*",
      var.session_table_arn, "${var.session_table_arn}/index/*",
    ]
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

  # User invites. identity/* because in the SES sandbox the recipient's
  # identity is authorized too.
  statement {
    actions = ["ses:SendEmail"]
    resources = [
      "arn:aws:ses:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:identity/*",
      var.ses_configuration_set_arn,
    ]
    condition {
      test     = "StringEquals"
      variable = "ses:FromAddress"
      values   = [var.email_from]
    }
  }

  statement {
    actions   = ["kms:GenerateMac", "kms:VerifyMac"]
    resources = [aws_kms_key.cursor.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:MacAlgorithm"
      values   = ["HMAC_SHA_256"]
    }
  }
}

module "admin" {
  source                 = "../lambda"
  name                   = "${var.name_prefix}-admin"
  zip_path               = var.zip_path
  code_signing           = var.code_signing
  policy_json            = data.aws_iam_policy_document.admin.json
  function_url_auth_type = "AWS_IAM"
  # Creating a user hashes a password with argon2id (see "Memory sized for
  # argon2id" in Architecture.md).
  memory_size = 1024
  timeout     = 30

  environment = {
    LITELOGIN_CONFIG_TABLE        = var.config_table_name
    LITELOGIN_SESSION_TABLE       = var.session_table_name
    LITELOGIN_CURSOR_KMS_KEY      = aws_kms_key.cursor.arn
    LITELOGIN_DEFAULT_HOST_DOMAIN = var.default_host_domain
    LITELOGIN_ROUTING_ENDPOINT    = var.custom_host_target
    LITELOGIN_EMAIL_FROM          = var.email_from
    LITELOGIN_SES_CONFIGURATION   = var.ses_configuration_set_name
  }
}

output "function_name" {
  value = module.admin.function_name
}

output "function_arn" {
  value = module.admin.function_arn
}

output "function_url" {
  value = module.admin.function_url
}
