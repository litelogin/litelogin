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

# Phase 0 placeholder: serves /healthz only. Phase 4 puts it behind
# CloudFront and adds the origin secret check.
data "aws_iam_policy_document" "auth" {
  statement {
    actions   = ["dynamodb:DescribeTable"]
    resources = [module.tables.config_table_arn, module.tables.session_table_arn]
  }
}

module "auth" {
  source                 = "../../modules/lambda"
  name                   = "${local.name_prefix}-auth"
  zip_path               = "${local.dist_dir}/auth.zip"
  policy_json            = data.aws_iam_policy_document.auth.json
  memory_size            = 1024
  function_url_auth_type = "NONE"

  environment = {
    LITELOGIN_CONFIG_TABLE  = module.tables.config_table_name
    LITELOGIN_SESSION_TABLE = module.tables.session_table_name
  }
}

output "config_table_name" {
  value = module.tables.config_table_name
}

output "session_table_name" {
  value = module.tables.session_table_name
}

output "auth_function_url" {
  value = module.auth.function_url
}
