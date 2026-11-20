# The admin console (Architecture.md, "Admin console"): its Lambda, behind
# its own CloudFront distribution on console.{domain}, and the SSM
# parameter holding its client's secret.
#
# The console is a client of LiteLogin, made with the CLI on the console
# org's login host. Its secret never passes through Terraform: `litelogin
# console rotate-secret` (the rotate_secret_command output) creates or
# replaces the parameter. Terraform doesn't manage it, because reading the
# resource would put the secret in the state, which the plan role reads.
#
# The distribution uses the default hosts' wildcard certificate and origin
# secret. On CloudFront's Free plan it has a plan, and a web ACL, of its
# own (a plan's web ACL can't be shared); otherwise it shares the login
# hosts' web ACL.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.72"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.12"
    }
  }
}

variable "name_prefix" {
  type = string
}

variable "zip_path" {
  description = "Path to the console Lambda package."
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

variable "domain" {
  description = "Parent domain of the default login hosts; the console is console.{domain}."
  type        = string
}

variable "zone_id" {
  description = "Route 53 zone of domain."
  type        = string
}

variable "certificate_arn" {
  description = "The validated wildcard certificate for *.{domain}."
  type        = string
}

variable "client_id" {
  description = "The console's client, a confidential client on the console org's login host."
  type        = string
}

variable "issuer" {
  description = "The console org's login host, e.g. https://login.example.com."
  type        = string
  validation {
    condition     = can(regex("^https://[a-z0-9.-]+$", var.issuer))
    error_message = "issuer must be an https origin with no path, like https://login.example.com."
  }
}

variable "origin_secret" {
  description = "The origin secret CloudFront sends."
  type        = string
  sensitive   = true
}

variable "origin_secret_hashes" {
  description = "SHA-256 (hex) of the origin secrets the Lambda accepts."
  type        = list(string)
}

variable "web_acl_arn" {
  description = "The login hosts' web ACL, shared when free_plan is false."
  type        = string
}

variable "free_plan" {
  description = "Put the distribution and a web ACL of its own on CloudFront's Free flat-rate plan."
  type        = bool
  default     = false
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
  description = "Customer managed key encrypting the tables, or null."
  type        = string
  default     = null
}

variable "cursor_key_arn" {
  description = "The Admin API's KMS HMAC key for pagination cursors."
  type        = string
}

variable "system_log_level" {
  type    = string
  default = "INFO"
}

variable "reduced_metrics" {
  type    = bool
  default = false
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  host          = "console.${var.domain}"
  origin_domain = regex("^https://([^/]+)/?$", module.console.function_url)[0]
  # A SecureString with SSM's AWS managed key, at no charge. Removing the
  # environment leaves it: delete it with aws ssm delete-parameter.
  secret_parameter     = "/${var.name_prefix}/console/client-secret"
  secret_parameter_arn = "arn:aws:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${local.secret_parameter}"
}

# ---- Lambda ----

data "aws_iam_policy_document" "console" {
  # The pages read configuration.
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:BatchGetItem"]
    resources = [var.config_table_arn, "${var.config_table_arn}/index/*"]
  }

  # Its own items in the Session table, and no others: a console can't
  # read or end a login host's sessions or tokens.
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"]
    resources = [var.session_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["CONSOLE_LOGIN#*", "CONSOLE_SESSION#*"]
    }
  }

  dynamic "statement" {
    for_each = var.table_kms_key_arn == null ? [] : [var.table_kms_key_arn]
    content {
      actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
      resources = [var.table_kms_key_arn]
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["dynamodb.${data.aws_region.current.region}.amazonaws.com"]
      }
    }
  }

  statement {
    actions   = ["kms:GenerateMac", "kms:VerifyMac"]
    resources = [var.cursor_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:MacAlgorithm"
      values   = ["HMAC_SHA_256"]
    }
  }

  # With SSM's AWS managed key, decrypting needs no KMS permission.
  statement {
    actions   = ["ssm:GetParameter"]
    resources = [local.secret_parameter_arn]
  }
}

module "console" {
  source                 = "../lambda"
  name                   = "${var.name_prefix}-console"
  zip_path               = var.zip_path
  code_signing           = var.code_signing
  policy_json            = data.aws_iam_policy_document.console.json
  function_url_auth_type = "NONE"
  memory_size            = 512
  system_log_level       = var.system_log_level

  environment = merge({
    LITELOGIN_CONFIG_TABLE             = var.config_table_name
    LITELOGIN_SESSION_TABLE            = var.session_table_name
    LITELOGIN_CONSOLE_URL              = "https://${local.host}"
    LITELOGIN_CONSOLE_ISSUER           = var.issuer
    LITELOGIN_CONSOLE_CLIENT_ID        = var.client_id
    LITELOGIN_CONSOLE_SECRET_PARAMETER = local.secret_parameter
    LITELOGIN_CURSOR_KMS_KEY           = var.cursor_key_arn
    LITELOGIN_DEFAULT_HOST_DOMAIN      = var.domain
    LITELOGIN_ORIGIN_SECRET_HASHES     = join(",", var.origin_secret_hashes)
  }, var.reduced_metrics ? { LITELOGIN_METRICS = "reduced" } : {})
}

# ---- CloudFront ----

# Only AWS managed policies, which the Free plan requires. Pages aren't
# cached and get every viewer header but Host (a function URL answers only
# to its own); static files have content-hashed paths and are cached.
data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_cache_policy" "optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

resource "aws_cloudfront_distribution" "console" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "${var.name_prefix} admin console (${local.host})"
  aliases         = [local.host]
  price_class     = var.free_plan ? "PriceClass_All" : "PriceClass_100"
  web_acl_id      = var.free_plan ? aws_wafv2_web_acl.console[0].arn : var.web_acl_arn
  http_version    = "http2and3"

  origin {
    origin_id   = "console"
    domain_name = local.origin_domain
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
      origin_read_timeout    = 30
    }
    custom_header {
      name  = "X-Litelogin-Origin-Secret"
      value = var.origin_secret
    }
  }

  default_cache_behavior {
    target_origin_id         = "console"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
    compress                 = true
  }

  ordered_cache_behavior {
    path_pattern           = "/static/*"
    target_origin_id       = "console"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = data.aws_cloudfront_cache_policy.optimized.id
    compress               = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = var.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# More specific than the login hosts' wildcard record, so it wins.
resource "aws_route53_record" "console" {
  for_each = toset(["A", "AAAA"])
  zone_id  = var.zone_id
  name     = local.host
  type     = each.value
  alias {
    name                   = aws_cloudfront_distribution.console.domain_name
    zone_id                = aws_cloudfront_distribution.console.hosted_zone_id
    evaluate_target_health = false
  }
}

# ---- WAF and the Free plan ----

# Only on the Free plan, which includes it. The rules the plan allows: a
# rate limit per IP and AWS managed rule groups.
resource "aws_wafv2_web_acl" "console" {
  count = var.free_plan ? 1 : 0
  name  = "${var.name_prefix}-console"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "global-rate"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-console-global-rate"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = {
      AWSManagedRulesAmazonIpReputationList = 10
      AWSManagedRulesCommonRuleSet          = 11
    }
    content {
      name     = rule.key
      priority = rule.value
      override_action {
        none {}
      }
      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = rule.key
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name_prefix}-console-${rule.key}"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-console"
    sampled_requests_enabled   = true
  }
}

# As in the edge module (plan.tf): turning the plan off waits for the
# cancellation to settle before CloudFront and WAF change.
resource "time_sleep" "plan_cancelled" {
  count            = var.free_plan ? 1 : 0
  destroy_duration = "3m"
  triggers = {
    distribution = aws_cloudfront_distribution.console.arn
    web_acl      = aws_wafv2_web_acl.console[0].arn
  }
}

resource "aws_pricingplanmanager_subscription" "free" {
  count       = var.free_plan ? 1 : 0
  plan_family = "CloudFront"
  plan_tier   = "FREE"
  resource_arns = [
    time_sleep.plan_cancelled[0].triggers.distribution,
    time_sleep.plan_cancelled[0].triggers.web_acl,
  ]
}

output "url" {
  value = "https://${local.host}"
}

output "function_name" {
  value = module.console.function_name
}

output "secret_parameter" {
  value = local.secret_parameter
}

output "rotate_secret_command" {
  description = "Run it once after the first deploy, and to rotate the secret."
  value       = "litelogin console rotate-secret --client ${var.client_id} --parameter ${local.secret_parameter}"
}
