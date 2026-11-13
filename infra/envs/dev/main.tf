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
  description = "AWS region for this environment. LiteLogin deploys to us-east-1 only."
  type        = string
}

variable "alarm_email" {
  description = "Address that gets alarm notifications (it must confirm the SNS subscription). Empty: none; subscribe to the alarm topic another way."
  type        = string
  default     = ""
}

variable "canary_start" {
  description = "Run the synthetic monitor. Set once its parameter holds the configuration (infra/modules/canary)."
  type        = bool
  # dev's parameter is set. The pipeline passes no variables, so a setting
  # dev needs belongs here, not in terraform.tfvars.
  default = true
}

variable "tracing" {
  description = "Trace the Auth Lambda with AWS X-Ray. Off by default: traces cost $5 per million requests (Cost.md)."
  type        = bool
  default     = false
}

variable "custom_hosts" {
  description = "Support custom login hosts (e.g. login.example.com), served through a CloudFront multi-tenant distribution. Remove every custom host before turning it off."
  type        = bool
  default     = true
}

variable "cloudfront_free_plan" {
  description = "Put the default login hosts' distribution, its WAF and the Route 53 zone on CloudFront's Free flat-rate plan, saving about $10.50 a month. It drops the sign-in endpoints' stricter rate limit and the loopback-redirects rule, which the plan doesn't allow (Cost.md). Needs custom_hosts = false."
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

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "litelogin"
      Environment = "dev"
    }
  }
}

module "litelogin" {
  source              = "../../modules/environment"
  environment         = "dev"
  default_host_domain = var.default_host_domain
  package_dir         = "${path.root}/../../../dist"

  # dev is disposable.
  deletion_protection = false

  alarm_email             = var.alarm_email
  canary_start            = var.canary_start
  tracing                 = var.tracing
  custom_hosts            = var.custom_hosts
  cloudfront_free_plan    = var.cloudfront_free_plan
  rate_limit_exempt_cidrs = var.rate_limit_exempt_cidrs
}

# The environment's resources moved into module.litelogin.
moved {
  from = module.dns
  to   = module.litelogin.module.dns
}

moved {
  from = module.kms
  to   = module.litelogin.module.kms
}

moved {
  from = module.tables
  to   = module.litelogin.module.tables
}

moved {
  from = module.signing
  to   = module.litelogin.module.signing
}

moved {
  from = module.codesigning
  to   = module.litelogin.module.codesigning
}

moved {
  from = module.auth
  to   = module.litelogin.module.auth
}

moved {
  from = module.edge
  to   = module.litelogin.module.edge
}

moved {
  from = module.email
  to   = module.litelogin.module.email
}

moved {
  from = module.admin
  to   = module.litelogin.module.admin
}

moved {
  from = module.jobs
  to   = module.litelogin.module.jobs
}

moved {
  from = module.monitoring
  to   = module.litelogin.module.monitoring
}

moved {
  from = module.canary
  to   = module.litelogin.module.canary
}

output "dns_name_servers" {
  description = "NS records to add for the default host domain at the parent domain's DNS provider."
  value       = module.litelogin.dns_name_servers
}

output "config_table_name" {
  value = module.litelogin.config_table_name
}

output "session_table_name" {
  value = module.litelogin.session_table_name
}

output "rotate_function_name" {
  value = module.litelogin.rotate_function_name
}

output "auth_function_url" {
  description = "Rejects requests that don't come through CloudFront."
  value       = module.litelogin.auth_function_url
}

output "edge_domain_name" {
  description = "The CloudFront distribution's own domain (no login host resolves on it)."
  value       = module.litelogin.edge_domain_name
}

output "admin_function_name" {
  value = module.litelogin.admin_function_name
}

output "admin_url" {
  description = "Admin API endpoint (AWS_IAM auth). Use with: litelogin --endpoint <url>, or litelogin configure --environment dev."
  value       = module.litelogin.admin_url
}

output "worker_function_name" {
  value = module.litelogin.worker_function_name
}

output "custom_host_cname_target" {
  description = "Where custom login hosts' CNAME records point. Null without custom hosts."
  value       = module.litelogin.custom_host_cname_target
}

output "dashboard" {
  description = "The environment's CloudWatch dashboard."
  value       = module.litelogin.dashboard
}

output "canary_parameter_name" {
  description = "SSM parameter holding the synthetic monitor's configuration (infra/modules/canary)."
  value       = module.litelogin.canary_parameter_name
}
