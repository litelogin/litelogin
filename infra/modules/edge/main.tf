# The edge in front of the Auth Lambda: a CloudFront distribution for the
# default login hosts ({label}.{domain}), with a wildcard certificate, WAF,
# and DNS in the domain's Route 53 zone.
#
# The Auth Lambda's function URL is public, so CloudFront proves a request
# came through it (and its WAF) with the origin secret, a custom origin
# header. The Lambda gets only the secret's SHA-256 hash. Two secrets, a
# and b, exist so the secret can rotate; see active_origin_secret.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6"
    }
  }
}

variable "name_prefix" {
  type = string
}

variable "domain" {
  description = "Parent domain of the default login hosts, e.g. login.example.com."
  type        = string
}

variable "zone_id" {
  description = "Route 53 zone of domain."
  type        = string
}

variable "function_url" {
  description = "The Auth Lambda's function URL."
  type        = string
}

variable "active_origin_secret" {
  description = <<-EOT
    Which origin secret CloudFront sends: "a" or "b". The Lambda accepts
    both. To rotate: replace the inactive one (terraform apply
    -replace='module.edge.random_password.origin["b"]'), deploy, switch
    this to it, and deploy again.
  EOT
  type        = string
  default     = "a"
  validation {
    condition     = contains(["a", "b"], var.active_origin_secret)
    error_message = "active_origin_secret must be \"a\" or \"b\"."
  }
}

variable "auth_rate_limit" {
  description = "Requests per IP per 5 minutes to the login, registration, password and token endpoints."
  type        = number
  default     = 300
}

variable "global_rate_limit" {
  description = "Requests per IP per 5 minutes to any endpoint."
  type        = number
  default     = 3000
}

locals {
  origin_domain = regex("^https://([^/]+)/?$", var.function_url)[0]
}

resource "random_password" "origin" {
  for_each = toset(["a", "b"])
  length   = 48
  special  = false
}

# ---- Certificate ----

resource "aws_acm_certificate" "wildcard" {
  domain_name       = "*.${var.domain}"
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for o in aws_acm_certificate.wildcard.domain_validation_options : o.domain_name => o
  }
  zone_id         = var.zone_id
  name            = each.value.resource_record_name
  type            = each.value.resource_record_type
  records         = [each.value.resource_record_value]
  ttl             = 300
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "wildcard" {
  certificate_arn         = aws_acm_certificate.wildcard.arn
  validation_record_fqdns = [for r in aws_route53_record.cert_validation : r.fqdn]
}

# ---- CloudFront ----

resource "aws_cloudfront_function" "host" {
  name    = "${var.name_prefix}-host"
  runtime = "cloudfront-js-2.0"
  comment = "Copies the viewer Host into x-litelogin-host"
  publish = true
  code    = file("${path.module}/host.js")
}

# What reaches the Lambda. Host isn't forwarded: a function URL only
# answers to its own Host.
resource "aws_cloudfront_origin_request_policy" "auth" {
  name = "${var.name_prefix}-auth"
  cookies_config {
    cookie_behavior = "all"
  }
  query_strings_config {
    query_string_behavior = "all"
  }
  headers_config {
    header_behavior = "whitelist"
    headers {
      items = [
        "x-litelogin-host", "CloudFront-Viewer-Address", "Origin", "Referer", "User-Agent",
        "Accept", "Accept-Language", "Content-Type",
      ]
      # Authorization can't go in an origin request policy: /token and
      # /userinfo get it through the api cache policy below.
    }
  }
}

# Discovery and JWKS are cacheable, per login host: the issuer differs by
# host, and the cache key must include it. The origin's Cache-Control
# decides how long, within these bounds.
resource "aws_cloudfront_cache_policy" "well_known" {
  name        = "${var.name_prefix}-well-known"
  min_ttl     = 0
  default_ttl = 300
  max_ttl     = 3600
  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
    cookies_config {
      cookie_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
    headers_config {
      header_behavior = "whitelist"
      headers {
        items = ["x-litelogin-host"]
      }
    }
  }
}

# /token and /userinfo need the Authorization header (client_secret_basic,
# bearer tokens), which CloudFront forwards only as part of a cache key.
# Their responses are no-store, so nothing is cached.
resource "aws_cloudfront_cache_policy" "api" {
  name        = "${var.name_prefix}-api"
  min_ttl     = 0
  default_ttl = 0
  max_ttl     = 1
  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "all"
    }
    headers_config {
      header_behavior = "whitelist"
      headers {
        items = ["Authorization", "x-litelogin-host"]
      }
    }
  }
}

# The rest of what /token and /userinfo need (headers in the cache policy
# can't be listed again here).
resource "aws_cloudfront_origin_request_policy" "api" {
  name = "${var.name_prefix}-api"
  cookies_config {
    cookie_behavior = "none"
  }
  query_strings_config {
    query_string_behavior = "none"
  }
  headers_config {
    header_behavior = "whitelist"
    headers {
      items = ["CloudFront-Viewer-Address", "Origin", "User-Agent", "Accept", "Content-Type"]
    }
  }
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

resource "aws_cloudfront_distribution" "this" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "${var.name_prefix} login hosts (*.${var.domain})"
  aliases         = ["*.${var.domain}"]
  price_class     = "PriceClass_100"
  web_acl_id      = aws_wafv2_web_acl.this.arn
  http_version    = "http2and3"

  origin {
    origin_id   = "auth"
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
      value = random_password.origin[var.active_origin_secret].result
    }
  }

  default_cache_behavior {
    target_origin_id         = "auth"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.auth.id
    compress                 = true
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.host.arn
    }
  }

  dynamic "ordered_cache_behavior" {
    for_each = ["/token", "/userinfo"]
    content {
      path_pattern             = ordered_cache_behavior.value
      target_origin_id         = "auth"
      viewer_protocol_policy   = "https-only"
      allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
      cached_methods           = ["GET", "HEAD"]
      cache_policy_id          = aws_cloudfront_cache_policy.api.id
      origin_request_policy_id = aws_cloudfront_origin_request_policy.api.id
      compress                 = true
      function_association {
        event_type   = "viewer-request"
        function_arn = aws_cloudfront_function.host.arn
      }
    }
  }

  ordered_cache_behavior {
    path_pattern           = "/.well-known/*"
    target_origin_id       = "auth"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = aws_cloudfront_cache_policy.well_known.id
    compress               = true
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.host.arn
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.wildcard.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

resource "aws_route53_record" "wildcard" {
  for_each = toset(["A", "AAAA"])
  zone_id  = var.zone_id
  name     = "*.${var.domain}"
  type     = each.value
  alias {
    name                   = aws_cloudfront_distribution.this.domain_name
    zone_id                = aws_cloudfront_distribution.this.hosted_zone_id
    evaluate_target_health = false
  }
}

# ---- WAF ----

# Common rule set rules that a loopback redirect_uri trips, and the labels
# they add (see the "loopback-redirects" rule), and the paths that carry
# one: /authorize and /logout in the query; in the body, the sign-in form
# (its pending authorization request), the logout confirmation, and the
# code exchange at /token (whose redirect_uri must repeat the request's).
locals {
  loopback_rules = {
    EC2MetaDataSSRF_QUERYARGUMENTS = "awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_QueryArguments"
    GenericRFI_QUERYARGUMENTS      = "awswaf:managed:aws:core-rule-set:GenericRFI_QueryArguments"
    EC2MetaDataSSRF_BODY           = "awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_Body"
    GenericRFI_BODY                = "awswaf:managed:aws:core-rule-set:GenericRFI_Body"
  }
  loopback_paths = ["/authorize", "/login", "/logout", "/token"]
}

variable "rate_limit_exempt_cidrs" {
  description = "IPv4 CIDRs the rate-based rules don't apply to, e.g. a load generator's address while a load test runs. Keep it empty otherwise."
  type        = list(string)
  default     = []
}

locals {
  rate_exempt      = length(var.rate_limit_exempt_cidrs) > 0
  auth_rate_prefix = ["/login", "/register", "/password/", "/token"]
}

resource "aws_wafv2_ip_set" "rate_exempt" {
  count              = local.rate_exempt ? 1 : 0
  name               = "${var.name_prefix}-rate-exempt"
  description        = "Addresses exempt from the rate-based rules, for load testing"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = var.rate_limit_exempt_cidrs

  # Delete it only after the web ACL stops referring to it; otherwise WAF
  # refuses (WAFAssociatedItemException).
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_wafv2_web_acl" "this" {
  name  = "${var.name_prefix}-edge"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "auth-endpoints-rate"
    priority = 0
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.auth_rate_limit
        aggregate_key_type = "IP"
        scope_down_statement {
          dynamic "or_statement" {
            for_each = local.rate_exempt ? [] : [1]
            content {
              dynamic "statement" {
                for_each = local.auth_rate_prefix
                content {
                  byte_match_statement {
                    search_string         = statement.value
                    positional_constraint = "STARTS_WITH"
                    field_to_match {
                      uri_path {}
                    }
                    text_transformation {
                      priority = 0
                      type     = "LOWERCASE"
                    }
                  }
                }
              }
            }
          }
          # With exempt addresses: the auth endpoints, from anywhere else.
          dynamic "and_statement" {
            for_each = local.rate_exempt ? [1] : []
            content {
              statement {
                or_statement {
                  dynamic "statement" {
                    for_each = local.auth_rate_prefix
                    content {
                      byte_match_statement {
                        search_string         = statement.value
                        positional_constraint = "STARTS_WITH"
                        field_to_match {
                          uri_path {}
                        }
                        text_transformation {
                          priority = 0
                          type     = "LOWERCASE"
                        }
                      }
                    }
                  }
                }
              }
              statement {
                not_statement {
                  statement {
                    ip_set_reference_statement {
                      arn = aws_wafv2_ip_set.rate_exempt[0].arn
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-auth-endpoints-rate"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "global-rate"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.global_rate_limit
        aggregate_key_type = "IP"
        dynamic "scope_down_statement" {
          for_each = local.rate_exempt ? [1] : []
          content {
            not_statement {
              statement {
                ip_set_reference_statement {
                  arn = aws_wafv2_ip_set.rate_exempt[0].arn
                }
              }
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-global-rate"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = {
      AWSManagedRulesAmazonIpReputationList = 10
      AWSManagedRulesCommonRuleSet          = 11
      AWSManagedRulesKnownBadInputsRuleSet  = 12
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

          # Counted here, blocked by the next rule outside sign-in and
          # logout (see "loopback-redirects").
          dynamic "rule_action_override" {
            for_each = rule.key == "AWSManagedRulesCommonRuleSet" ? keys(local.loopback_rules) : []
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name_prefix}-${rule.key}"
        sampled_requests_enabled   = true
      }
    }
  }

  # The EC2MetaDataSSRF and GenericRFI rules block a URL with a loopback
  # address or an IP in the query string or body, which a native app's or
  # CLI's loopback redirect_uri always is (http://127.0.0.1:{port}/callback,
  # RFC 8252 section 7.3). LiteLogin never fetches a redirect URI, only
  # redirects the browser to one, so the rules are relaxed on the paths
  # that carry one and block everywhere else.
  rule {
    name     = "loopback-redirects"
    priority = 13
    action {
      block {}
    }
    statement {
      and_statement {
        statement {
          or_statement {
            dynamic "statement" {
              for_each = values(local.loopback_rules)
              content {
                label_match_statement {
                  scope = "LABEL"
                  key   = statement.value
                }
              }
            }
          }
        }
        statement {
          not_statement {
            statement {
              or_statement {
                dynamic "statement" {
                  for_each = local.loopback_paths
                  content {
                    byte_match_statement {
                      search_string         = statement.value
                      positional_constraint = "EXACTLY"
                      field_to_match {
                        uri_path {}
                      }
                      text_transformation {
                        priority = 0
                        type     = "NONE"
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-loopback-redirects"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-edge"
    sampled_requests_enabled   = true
  }
}

output "distribution_domain_name" {
  value = aws_cloudfront_distribution.this.domain_name
}

output "distribution_id" {
  value = aws_cloudfront_distribution.this.id
}

output "origin_secret_hashes" {
  description = "SHA-256 (hex) of both origin secrets, for the Auth Lambda."
  value       = [for k in ["a", "b"] : sha256(random_password.origin[k].result)]
}
