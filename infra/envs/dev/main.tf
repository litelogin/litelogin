# The dev environment.
#
# Initialize with a backend config file (see backend.hcl.example):
#   tofu init -backend-config=backend.hcl

terraform {
  # 1.10 is the first release with native S3 state locking (use_lockfile).
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

  # Bucket, key and region come from backend.hcl.
  backend "s3" {
    use_lockfile = true
    encrypt      = true
  }
}

variable "region" {
  description = "AWS region for this environment."
  type        = string
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

variable "default_host_domain" {
  description = "Parent domain of default login hosts ({label}.{domain}). Its DNS is a Route 53 zone in this account, delegated from the parent domain."
  type        = string
  default     = "dev.litelogin.com"
}

locals {
  name_prefix = "litelogin-dev"
  dist_dir    = "${path.root}/../../../dist"
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "litelogin"
      Environment = "dev"
    }
  }
}

module "dns" {
  source = "../../modules/dns"
  domain = var.default_host_domain
}

module "kms" {
  source      = "../../modules/kms"
  name_prefix = local.name_prefix
}

module "tables" {
  source      = "../../modules/tables"
  name_prefix = local.name_prefix
  kms_key_arn = module.kms.tables_key_arn

  # dev is disposable.
  deletion_protection = false
}

module "signing" {
  source             = "../../modules/signing"
  name_prefix        = local.name_prefix
  environment        = "dev"
  zip_path           = "${local.dist_dir}/rotate.zip"
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
  # Signing tokens (used from Phase 5).
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
  source      = "../../modules/codesigning"
  name_prefix = local.name_prefix
}

module "auth" {
  source                 = "../../modules/lambda"
  name                   = "${local.name_prefix}-auth"
  zip_path               = "${local.dist_dir}/auth.zip"
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
  source       = "../../modules/edge"
  name_prefix  = local.name_prefix
  domain       = var.default_host_domain
  zone_id      = module.dns.zone_id
  function_url = module.auth.function_url

  rate_limit_exempt_cidrs = var.rate_limit_exempt_cidrs
}

module "email" {
  source      = "../../modules/email"
  name_prefix = local.name_prefix
  domain      = var.default_host_domain
  zone_id     = module.dns.zone_id
}

module "admin" {
  source              = "../../modules/admin"
  name_prefix         = local.name_prefix
  zip_path            = "${local.dist_dir}/admin.zip"
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
  source             = "../../modules/jobs"
  name_prefix        = local.name_prefix
  zip_path           = "${local.dist_dir}/worker.zip"
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
  source      = "../../modules/monitoring"
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
  source        = "../../modules/canary"
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
  description = "Admin API endpoint (AWS_IAM auth). Use with: litelogin --endpoint <url>, or litelogin configure --environment dev."
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
  value       = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards/dashboard/${module.monitoring.dashboard_name}"
}

output "canary_secret_arn" {
  description = "Secret holding the synthetic monitor's configuration (infra/modules/canary)."
  value       = module.canary.secret_arn
}
