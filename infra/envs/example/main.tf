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

variable "canary_start" {
  description = "Run the synthetic monitor once its secret holds the configuration (SelfHosting.md, \"Monitoring\")."
  type        = bool
  default     = false
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

module "litelogin" {
  source              = "../../modules/environment"
  environment         = var.environment
  default_host_domain = var.default_host_domain
  package_dir         = "${path.root}/../../../dist"

  alarm_email             = var.alarm_email
  canary_start            = var.canary_start
  rate_limit_exempt_cidrs = var.rate_limit_exempt_cidrs
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
  description = "Where custom login hosts' CNAME records point."
  value       = module.litelogin.custom_host_cname_target
}

output "dashboard" {
  description = "The environment's CloudWatch dashboard."
  value       = module.litelogin.dashboard
}

output "canary_secret_arn" {
  description = "Secret holding the synthetic monitor's configuration."
  value       = module.litelogin.canary_secret_arn
}
