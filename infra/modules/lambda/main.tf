# A LiteLogin Lambda function on arm64, with its own IAM role, log group and
# optional function URL. By default it is a Go `bootstrap` binary on
# provided.al2023.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "name" {
  description = "Function name, e.g. litelogin-dev-auth."
  type        = string
}

variable "zip_path" {
  description = "Path to the deployment zip, e.g. the bootstrap binary built by `make package`."
  type        = string
}

variable "runtime" {
  description = "Lambda runtime."
  type        = string
  default     = "provided.al2023"
}

variable "handler" {
  description = "Handler: `bootstrap` for a Go binary, or `file.export` for Node.js."
  type        = string
  default     = "bootstrap"
}

variable "policy_json" {
  description = "IAM policy document with the function's permissions, beyond writing its own logs. Required: it's usually only known at apply time, so it can't decide whether the policy exists."
  type        = string
}

variable "environment" {
  description = "Environment variables."
  type        = map(string)
  default     = {}
}

variable "memory_size" {
  description = "Memory in MB. CPU scales with memory."
  type        = number
  default     = 512
}

variable "timeout" {
  description = "Timeout in seconds."
  type        = number
  default     = 10
}

variable "reserved_concurrency" {
  description = "Reserved concurrent executions; -1 for none."
  type        = number
  default     = -1
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "code_signing" {
  description = "Sign the package and only accept signed code (the codesigning module's code_signing output). Null: deploy the zip unsigned."
  type = object({
    bucket       = string
    profile_name = string
    config_arn   = string
  })
  default = null
}

variable "system_log_level" {
  description = "Lambda's own log lines kept: INFO keeps each invocation's platform.start and platform.report lines; WARN drops them (reduced monitoring, Cost.md)."
  type        = string
  default     = "INFO"
  validation {
    condition     = contains(["DEBUG", "INFO", "WARN"], var.system_log_level)
    error_message = "system_log_level must be DEBUG, INFO or WARN."
  }
}

variable "tracing" {
  description = "Trace invocations with AWS X-Ray (active tracing)."
  type        = bool
  default     = false
}

variable "function_url_auth_type" {
  description = "NONE or AWS_IAM to create a function URL, or null for no function URL."
  type        = string
  default     = null

  validation {
    condition     = var.function_url_auth_type == null || contains(["NONE", "AWS_IAM"], coalesce(var.function_url_auth_type, "NONE"))
    error_message = "function_url_auth_type must be NONE, AWS_IAM or null."
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = var.name
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.this.arn}:*"]
  }
}

resource "aws_iam_role_policy" "logs" {
  name   = "logs"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.logs.json
}

resource "aws_iam_role_policy" "permissions" {
  name   = "permissions"
  role   = aws_iam_role.this.id
  policy = var.policy_json
}

# ---- Signed package ----

locals {
  signed = var.code_signing != null
}

# Keyed by content, so a new build is a new object and a new signing job,
# and an unchanged one is neither.
resource "aws_s3_object" "package" {
  count       = local.signed ? 1 : 0
  bucket      = var.code_signing.bucket
  key         = "packages/${var.name}/${filesha256(var.zip_path)}.zip"
  source      = var.zip_path
  source_hash = filemd5(var.zip_path)
}

resource "aws_signer_signing_job" "package" {
  count        = local.signed ? 1 : 0
  profile_name = var.code_signing.profile_name

  source {
    s3 {
      bucket  = aws_s3_object.package[0].bucket
      key     = aws_s3_object.package[0].key
      version = aws_s3_object.package[0].version_id
    }
  }

  destination {
    s3 {
      bucket = var.code_signing.bucket
      prefix = "signed/${var.name}/"
    }
  }

  ignore_signing_job_failure = false
}

resource "aws_lambda_function" "this" {
  function_name = var.name
  role          = aws_iam_role.this.arn
  runtime       = var.runtime
  handler       = var.handler
  architectures = ["arm64"]
  memory_size   = var.memory_size
  timeout       = var.timeout

  # Unsigned: the local zip. Signed: the signing job's copy, which changes
  # whenever the package does.
  filename         = local.signed ? null : var.zip_path
  source_code_hash = local.signed ? null : filebase64sha256(var.zip_path)
  s3_bucket        = local.signed ? aws_signer_signing_job.package[0].signed_object[0].s3[0].bucket : null
  s3_key           = local.signed ? aws_signer_signing_job.package[0].signed_object[0].s3[0].key : null

  code_signing_config_arn = local.signed ? var.code_signing.config_arn : null

  reserved_concurrent_executions = var.reserved_concurrency

  environment {
    variables = var.environment
  }

  # Always set: the block is computed, so leaving it out wouldn't turn
  # active tracing off.
  tracing_config {
    mode = var.tracing ? "Active" : "PassThrough"
  }

  # The Go functions write JSON logs with log/slog. The system log level
  # is always set: it's computed, so leaving it out wouldn't put it back.
  logging_config {
    log_format       = "JSON"
    log_group        = aws_cloudwatch_log_group.this.name
    system_log_level = var.system_log_level
  }

  depends_on = [aws_iam_role_policy.logs]
}

resource "aws_lambda_function_url" "this" {
  count              = var.function_url_auth_type == null ? 0 : 1
  function_name      = aws_lambda_function.this.function_name
  authorization_type = var.function_url_auth_type
}

# A public (NONE) function URL needs a resource policy that allows anyone to
# invoke it. The Auth Lambda protects itself with the origin secret instead
# (Architecture.md, "Origin: Lambda function URLs").
resource "aws_lambda_permission" "public_url" {
  count                  = var.function_url_auth_type == "NONE" ? 1 : 0
  statement_id           = "AllowPublicFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.this.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_iam_role_policy_attachment" "xray" {
  count      = var.tracing ? 1 : 0
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

output "function_name" {
  value = aws_lambda_function.this.function_name
}

output "function_arn" {
  value = aws_lambda_function.this.arn
}

output "role_arn" {
  value = aws_iam_role.this.arn
}

output "function_url" {
  value = var.function_url_auth_type == null ? null : aws_lambda_function_url.this[0].function_url
}
