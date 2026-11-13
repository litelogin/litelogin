# A whole LiteLogin environment in one AWS account: tables, signing keys,
# the Auth, Admin, Worker and Rotate Lambdas, CloudFront and WAF, email
# and monitoring. Each environment's root module (infra/envs/*)
# configures the AWS provider and state backend and calls this module;
# a self-hosted deployment does the same (SelfHosting.md).
#
# Resource names start with litelogin-<environment>. The CLI's
# --environment flag finds the Admin API by that name.

terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

variable "environment" {
  description = "Environment name, e.g. dev, qa, prod or your own: lower case letters and digits. Resources are named litelogin-<environment>-*."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,15}$", var.environment))
    error_message = "environment must be 2 to 16 lower case letters and digits, starting with a letter."
  }
}

variable "default_host_domain" {
  description = "Parent domain of the default login hosts ({label}.{domain}), e.g. login.example.com. This module creates its Route 53 zone; delegate the domain to the zone's name servers (the dns_name_servers output)."
  type        = string
}

variable "package_dir" {
  description = "Directory holding the Lambda packages built by make package (auth.zip, admin.zip, worker.zip, rotate.zip)."
  type        = string
}

variable "deletion_protection" {
  description = "Protect the tables from deletion. Turn it off only for disposable environments."
  type        = bool
  default     = true
}

variable "alarm_email" {
  description = "Address that gets alarm notifications (it must confirm the SNS subscription). Empty: none; subscribe to the alarm topic another way."
  type        = string
  default     = ""
}

variable "setup" {
  description = "\"full\": pay-as-you-go CloudFront with custom login hosts and the full WAF, X-Ray tracing, every metric and log line, and the dashboard. \"lean\": for small deployments, about $15 a month less: CloudFront's Free flat-rate plan, default login hosts only, and reduced monitoring (Cost.md, \"Setups\"). Each override below defaults to null, which follows the setup."
  type        = string
  default     = "full"
  validation {
    condition     = contains(["lean", "full"], var.setup)
    error_message = "setup must be \"lean\" or \"full\"."
  }
}

variable "cloudfront_plan" {
  description = "Override: \"free\" puts the default login hosts' distribution, its WAF and the Route 53 zone on CloudFront's Free flat-rate plan, about $10.50 a month less. Its WAF drops the sign-in endpoints' stricter rate limit and the loopback-redirects rule, which the plan doesn't allow, and nothing is cached at the edge (Cost.md). It needs custom_hosts = false and no rate_limit_exempt_cidrs. \"pay-as-you-go\": the full WAF and edge caching. Lean: free; full: pay-as-you-go."
  type        = string
  default     = null
  validation {
    condition     = var.cloudfront_plan == null || contains(["free", "pay-as-you-go"], coalesce(var.cloudfront_plan, "free"))
    error_message = "cloudfront_plan must be \"free\" or \"pay-as-you-go\"."
  }
}

variable "custom_hosts" {
  description = "Override: support custom login hosts (e.g. login.example.com), served through a CloudFront multi-tenant distribution. Remove every custom host before turning it off. Lean: false; full: true."
  type        = bool
  default     = null
}

variable "tracing" {
  description = "Override: \"xray\" traces the Auth Lambda with AWS X-Ray, at $5 per million requests (Cost.md); \"off\" doesn't. Lean: off; full: xray."
  type        = string
  default     = null
  validation {
    condition     = var.tracing == null || contains(["xray", "off"], coalesce(var.tracing, "off"))
    error_message = "tracing must be \"xray\" or \"off\"."
  }
}

variable "metrics" {
  description = "Override: \"all\" publishes every custom metric; \"alarmed\" only the 3 that alarms use, with the rest as log fields, and one Lambda throttles alarm for the account instead of one per function (Cost.md, \"Reduced monitoring\"). Lean: alarmed; full: all."
  type        = string
  default     = null
  validation {
    condition     = var.metrics == null || contains(["all", "alarmed"], coalesce(var.metrics, "all"))
    error_message = "metrics must be \"all\" or \"alarmed\"."
  }
}

variable "dashboard" {
  description = "Override: create the CloudWatch dashboard ($3 a month). It needs metrics = \"all\". Lean: false; full: true."
  type        = bool
  default     = null
}

variable "lambda_logs" {
  description = "Override: \"all\" logs Lambda's platform lines for every invocation; \"failures\" only for crashes and timeouts (Cost.md, \"Reduced monitoring\"). Application logs aren't affected. Lean: failures; full: all."
  type        = string
  default     = null
  validation {
    condition     = var.lambda_logs == null || contains(["all", "failures"], coalesce(var.lambda_logs, "all"))
    error_message = "lambda_logs must be \"all\" or \"failures\"."
  }
}

variable "rate_limit_exempt_cidrs" {
  description = "Addresses exempt from WAF rate limits, only while a load test runs (test/load/README.md)."
  type        = list(string)
  default     = []
}

locals {
  name_prefix = "litelogin-${var.environment}"

  # Each setting: its override, or the setup's default.
  lean             = var.setup == "lean"
  cloudfront_plan  = coalesce(var.cloudfront_plan, local.lean ? "free" : "pay-as-you-go")
  custom_hosts     = coalesce(var.custom_hosts, !local.lean)
  tracing          = coalesce(var.tracing, local.lean ? "off" : "xray")
  metrics          = coalesce(var.metrics, local.lean ? "alarmed" : "all")
  dashboard        = coalesce(var.dashboard, !local.lean)
  lambda_logs      = coalesce(var.lambda_logs, local.lean ? "failures" : "all")
  free_plan        = local.cloudfront_plan == "free"
  reduced_metrics  = local.metrics == "alarmed"
  system_log_level = local.lambda_logs == "failures" ? "WARN" : "INFO"
}

# CloudFront's certificate and WAF, and the Worker's certificate
# management, must be in us-east-1. It also checks settings that depend on
# each other.
resource "terraform_data" "region" {
  lifecycle {
    precondition {
      condition     = data.aws_region.current.region == "us-east-1"
      error_message = "LiteLogin deploys to us-east-1 only: CloudFront certificates and WAF web ACLs must be there."
    }
    precondition {
      condition     = !(local.dashboard && local.reduced_metrics)
      error_message = "dashboard = true needs metrics = \"all\": most of the dashboard's metrics are log fields with \"alarmed\"."
    }
  }
}

module "dns" {
  source = "../dns"
  domain = var.default_host_domain
}

module "kms" {
  source      = "../kms"
  name_prefix = local.name_prefix
}

module "tables" {
  source      = "../tables"
  name_prefix = local.name_prefix
  kms_key_arn = module.kms.tables_key_arn

  deletion_protection = var.deletion_protection
}

module "signing" {
  source             = "../signing"
  name_prefix        = local.name_prefix
  environment        = var.environment
  zip_path           = "${var.package_dir}/rotate.zip"
  code_signing       = module.codesigning.code_signing
  config_table_name  = module.tables.config_table_name
  config_table_arn   = module.tables.config_table_arn
  session_table_name = module.tables.session_table_name
  table_kms_key_arn  = module.kms.tables_key_arn
  system_log_level   = local.system_log_level
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# The Auth Lambda serves the login hosts, behind CloudFront (module.edge).
data "aws_iam_policy_document" "auth" {
  # Signing tokens.
  source_policy_documents = [module.signing.sign_policy_json]

  statement {
    actions = [
      "dynamodb:DescribeTable", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem",
      "dynamodb:Query", "dynamodb:BatchWriteItem", "dynamodb:ConditionCheckItem",
    ]
    resources = [
      module.tables.config_table_arn, "${module.tables.config_table_arn}/index/*",
      module.tables.session_table_arn, "${module.tables.session_table_arn}/index/*",
    ]
  }

  statement {
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = [module.kms.tables_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["dynamodb.${data.aws_region.current.region}.amazonaws.com"]
    }
  }

  # Sending only from the environment's address. identity/* because in the
  # SES sandbox the recipient's identity is authorized too.
  statement {
    actions = ["ses:SendEmail"]
    resources = [
      "arn:aws:ses:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:identity/*",
      module.email.configuration_set_arn,
    ]
    condition {
      test     = "StringEquals"
      variable = "ses:FromAddress"
      values   = [module.email.from_address]
    }
  }
}

module "codesigning" {
  source      = "../codesigning"
  name_prefix = local.name_prefix
}

module "auth" {
  source                 = "../lambda"
  name                   = "${local.name_prefix}-auth"
  zip_path               = "${var.package_dir}/auth.zip"
  code_signing           = module.codesigning.code_signing
  policy_json            = data.aws_iam_policy_document.auth.json
  memory_size            = 1024
  function_url_auth_type = "NONE"
  tracing                = local.tracing == "xray"
  system_log_level       = local.system_log_level

  environment = merge({
    LITELOGIN_CONFIG_TABLE         = module.tables.config_table_name
    LITELOGIN_SESSION_TABLE        = module.tables.session_table_name
    LITELOGIN_ORIGIN_SECRET_HASHES = join(",", module.edge.origin_secret_hashes)
    LITELOGIN_EMAIL_FROM           = module.email.from_address
    LITELOGIN_SES_CONFIGURATION    = module.email.configuration_set_name
  }, local.reduced_metrics ? { LITELOGIN_METRICS = "reduced" } : {})
}

module "edge" {
  source       = "../edge"
  name_prefix  = local.name_prefix
  domain       = var.default_host_domain
  zone_id      = module.dns.zone_id
  function_url = module.auth.function_url
  custom_hosts = local.custom_hosts
  free_plan    = local.free_plan

  rate_limit_exempt_cidrs = var.rate_limit_exempt_cidrs
}

module "email" {
  source      = "../email"
  name_prefix = local.name_prefix
  domain      = var.default_host_domain
  zone_id     = module.dns.zone_id
}

module "admin" {
  source              = "../admin"
  name_prefix         = local.name_prefix
  zip_path            = "${var.package_dir}/admin.zip"
  code_signing        = module.codesigning.code_signing
  config_table_name   = module.tables.config_table_name
  config_table_arn    = module.tables.config_table_arn
  session_table_name  = module.tables.session_table_name
  session_table_arn   = module.tables.session_table_arn
  table_kms_key_arn   = module.kms.tables_key_arn
  default_host_domain = var.default_host_domain

  email_from                 = module.email.from_address
  ses_configuration_set_name = module.email.configuration_set_name
  ses_configuration_set_arn  = module.email.configuration_set_arn
  custom_host_target         = local.custom_hosts ? module.edge.routing_endpoint : ""
  system_log_level           = local.system_log_level
  reduced_metrics            = local.reduced_metrics
}

module "jobs" {
  source             = "../jobs"
  name_prefix        = local.name_prefix
  zip_path           = "${var.package_dir}/worker.zip"
  code_signing       = module.codesigning.code_signing
  config_table_name  = module.tables.config_table_name
  config_table_arn   = module.tables.config_table_arn
  config_stream_arn  = module.tables.config_stream_arn
  session_table_name = module.tables.session_table_name
  session_table_arn  = module.tables.session_table_arn
  table_kms_key_arn  = module.kms.tables_key_arn

  custom_hosts = local.custom_hosts ? {
    distribution_id      = module.edge.tenant_distribution_id
    distribution_arn     = module.edge.tenant_distribution_arn
    connection_group_id  = module.edge.connection_group_id
    connection_group_arn = module.edge.connection_group_arn
    routing_endpoint     = module.edge.routing_endpoint
  } : null

  system_log_level = local.system_log_level
  reduced_metrics  = local.reduced_metrics
  alarm_actions    = [module.monitoring.alarm_topic_arn]
}

module "monitoring" {
  source          = "../monitoring"
  name_prefix     = local.name_prefix
  alarm_email     = var.alarm_email
  reduced_metrics = local.reduced_metrics
  dashboard       = local.dashboard
  function_names = {
    auth   = module.auth.function_name
    admin  = module.admin.function_name
    worker = module.jobs.worker_function_name
    rotate = module.signing.rotate_function_name
  }
  table_names = [module.tables.config_table_name, module.tables.session_table_name]
}

output "dns_name_servers" {
  description = "NS records to add for the default host domain at the parent domain's DNS provider."
  value       = module.dns.name_servers
}

output "config_table_name" {
  value = module.tables.config_table_name
}

output "session_table_name" {
  value = module.tables.session_table_name
}

output "rotate_function_name" {
  value = module.signing.rotate_function_name
}

output "auth_function_url" {
  description = "Rejects requests that don't come through CloudFront."
  value       = module.auth.function_url
}

output "edge_domain_name" {
  description = "The CloudFront distribution's own domain (no login host resolves on it)."
  value       = module.edge.distribution_domain_name
}

output "admin_function_name" {
  value = module.admin.function_name
}

output "admin_url" {
  description = "Admin API endpoint (AWS_IAM auth). Use with: litelogin --endpoint <url>, or litelogin configure --environment <environment>."
  value       = module.admin.function_url
}

output "worker_function_name" {
  value = module.jobs.worker_function_name
}

output "custom_host_cname_target" {
  description = "Where custom login hosts' CNAME records point. Null without custom hosts."
  value       = module.edge.routing_endpoint
}

output "dashboard" {
  description = "The environment's CloudWatch dashboard, or null without it."
  value       = !local.dashboard ? null : "https://${data.aws_region.current.region}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.region}#dashboards/dashboard/${module.monitoring.dashboard_name}"
}

