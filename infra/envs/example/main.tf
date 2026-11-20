# A LiteLogin environment for a self-hosted deployment: copy this
# directory to infra/envs/<environment> and follow SelfHosting.md.
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
  }

  # Bucket, key and region come from backend.hcl.
  backend "s3" {
    use_lockfile = true
    encrypt      = true
  }
}

variable "environment" {
  description = "Environment name: resources are named litelogin-<environment>-*, and the CLI finds the deployment by it (litelogin --environment <environment>)."
  type        = string
}

variable "default_host_domain" {
  description = "Parent domain of the default login hosts ({label}.{domain}), e.g. login.example.com. Delegate it to the dns_name_servers output."
  type        = string
}

variable "alarm_email" {
  description = "Address that gets alarm notifications (it must confirm the SNS subscription). Empty: none."
  type        = string
  default     = ""
}

variable "setup" {
  description = "\"lean\" or \"full\": the defaults for CloudFront, the WAF, tracing, metrics, the dashboard, Lambda's logs and table encryption (Cost.md, \"Setups\"; infra/modules/environment)."
  type        = string
  default     = "full"
}

# Overrides of the setup's defaults; null follows the setup. Each is
# described in infra/modules/environment.
variable "cloudfront_plan" {
  description = "\"free\" or \"pay-as-you-go\"."
  type        = string
  default     = null
}

variable "custom_hosts" {
  description = "Support custom login hosts."
  type        = bool
  default     = null
}

variable "tracing" {
  description = "\"xray\" or \"off\"."
  type        = string
  default     = null
}

variable "metrics" {
  description = "\"all\" or \"alarmed\"."
  type        = string
  default     = null
}

variable "dashboard" {
  description = "Create the CloudWatch dashboard."
  type        = bool
  default     = null
}

variable "lambda_logs" {
  description = "\"all\" or \"failures\"."
  type        = string
  default     = null
}

variable "table_encryption" {
  description = "\"aws-owned\" or \"customer-managed\"."
  type        = string
  default     = null
}


variable "rate_limit_exempt_cidrs" {
  description = "Addresses exempt from WAF rate limits, only while a load test runs (test/load/README.md)."
  type        = list(string)
  default     = []
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "litelogin"
      Environment = var.environment
    }
  }
}

variable "console" {
  description = "The admin console, on console.{default_host_domain}: client_id is its client and issuer the console org's login host, e.g. https://login.example.com (SelfHosting.md, \"Admin console\"). Null: no console."
  type = object({
    client_id = string
    issuer    = string
  })
  default = null
}

module "litelogin" {
  source              = "../../modules/environment"
  environment         = var.environment
  default_host_domain = var.default_host_domain
  package_dir         = "${path.root}/../../../dist"

  alarm_email             = var.alarm_email
  setup                   = var.setup
  cloudfront_plan         = var.cloudfront_plan
  custom_hosts            = var.custom_hosts
  tracing                 = var.tracing
  metrics                 = var.metrics
  dashboard               = var.dashboard
  lambda_logs             = var.lambda_logs
  table_encryption        = var.table_encryption
  rate_limit_exempt_cidrs = var.rate_limit_exempt_cidrs
  console                 = var.console
}

output "dns_name_servers" {
  description = "NS records to add for default_host_domain at its parent domain's DNS provider."
  value       = module.litelogin.dns_name_servers
}

output "admin_url" {
  description = "Admin API endpoint (AWS_IAM auth)."
  value       = module.litelogin.admin_url
}

output "admin_function_name" {
  value = module.litelogin.admin_function_name
}

output "rotate_function_name" {
  value = module.litelogin.rotate_function_name
}

output "edge_domain_name" {
  description = "The CloudFront distribution's own domain (no login host resolves on it)."
  value       = module.litelogin.edge_domain_name
}

output "auth_function_url" {
  description = "Rejects requests that don't come through CloudFront."
  value       = module.litelogin.auth_function_url
}

output "custom_host_cname_target" {
  description = "Where custom login hosts' CNAME records point. Null without custom hosts."
  value       = module.litelogin.custom_host_cname_target
}

output "dashboard" {
  description = "The environment's CloudWatch dashboard, or null without it."
  value       = module.litelogin.dashboard
}

output "console_url" {
  description = "The admin console, or null without it."
  value       = module.litelogin.console_url
}

output "console_rotate_secret_command" {
  description = "Gives the console's client a new secret, stored where the console reads it. Run it after the first deploy, and to rotate."
  value       = module.litelogin.console_rotate_secret_command
}
