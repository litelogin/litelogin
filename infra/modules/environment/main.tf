# A whole LiteLogin environment in one AWS account: tables, signing keys,
# the Auth, Admin, Worker and Rotate Lambdas, CloudFront and WAF, email,
# monitoring and the canary. Each environment's root module (infra/envs/*)
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
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
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

variable "canary_start" {
  description = "Run the synthetic monitor. Set once its secret holds the configuration (infra/modules/canary)."
  type        = bool
  default     = false
}

variable "rate_limit_exempt_cidrs" {
  description = "Addresses exempt from WAF rate limits, only while a load test runs (test/load/README.md)."
  type        = list(string)
  default     = []
}

locals {
  name_prefix = "litelogin-${var.environment}"
}

# CloudFront's certificate and WAF, and the Worker's certificate
# management, must be in us-east-1.
resource "terraform_data" "region" {
  lifecycle {
    precondition {
      condition     = data.aws_region.current.region == "us-east-1"
      error_message = "LiteLogin deploys to us-east-1 only: CloudFront certificates and WAF web ACLs must be there."
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
  tracing                = true

  environment = {
    LITELOGIN_CONFIG_TABLE         = module.tables.config_table_name
    LITELOGIN_SESSION_TABLE        = module.tables.session_table_name
    LITELOGIN_ORIGIN_SECRET_HASHES = join(",", module.edge.origin_secret_hashes)
    LITELOGIN_EMAIL_FROM           = module.email.from_address
    LITELOGIN_SES_CONFIGURATION    = module.email.configuration_set_name
  }
}

module "edge" {
  source       = "../edge"
  name_prefix  = local.name_prefix
  domain       = var.default_host_domain
  zone_id      = module.dns.zone_id
  function_url = module.auth.function_url

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
  custom_host_target         = module.edge.routing_endpoint
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

  custom_hosts = {
    distribution_id      = module.edge.tenant_distribution_id
    distribution_arn     = module.edge.tenant_distribution_arn
    connection_group_id  = module.edge.connection_group_id
    connection_group_arn = module.edge.connection_group_arn
    routing_endpoint     = module.edge.routing_endpoint
  }

  alarm_actions = [module.monitoring.alarm_topic_arn]
}

module "monitoring" {
  source      = "../monitoring"
  name_prefix = local.name_prefix
  alarm_email = var.alarm_email
  function_names = {
    auth   = module.auth.function_name
    admin  = module.admin.function_name
    worker = module.jobs.worker_function_name
    rotate = module.signing.rotate_function_name
  }
  table_names = [module.tables.config_table_name, module.tables.session_table_name]
}

module "canary" {
  source        = "../canary"
  name_prefix   = local.name_prefix
  start         = var.canary_start
  alarm_actions = [module.monitoring.alarm_topic_arn]
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
  description = "Where custom login hosts' CNAME records point."
  value       = module.edge.routing_endpoint
}

output "dashboard" {
  description = "The environment's CloudWatch dashboard."
  value       = "https://${data.aws_region.current.region}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.region}#dashboards/dashboard/${module.monitoring.dashboard_name}"
}

output "canary_secret_arn" {
  description = "Secret holding the synthetic monitor's configuration (infra/modules/canary)."
  value       = module.canary.secret_arn
}
