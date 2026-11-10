# A LiteLogin Lambda function: a Go `bootstrap` binary on provided.al2023
# (arm64), with its own IAM role, log group and optional function URL.

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
  description = "Path to the deployment zip containing the bootstrap binary (built by `make package`)."
  type        = string
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

resource "aws_lambda_function" "this" {
  function_name    = var.name
  role             = aws_iam_role.this.arn
  runtime          = "provided.al2023"
  handler          = "bootstrap"
  architectures    = ["arm64"]
  filename         = var.zip_path
  source_code_hash = filebase64sha256(var.zip_path)
  memory_size      = var.memory_size
  timeout          = var.timeout

  reserved_concurrent_executions = var.reserved_concurrency

  environment {
    variables = var.environment
  }

  # The functions write JSON logs with log/slog.
  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.this.name
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
