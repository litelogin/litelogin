# Custom login hosts (e.g. login.acme.com) are tenants of a multi-tenant
# distribution (CloudFront SaaS Manager), one per host, each with a
# CloudFront-managed certificate. The Worker creates and deletes the
# tenants; Terraform owns only the distribution and its connection group.
#
# The customer points a CNAME at the connection group's routing endpoint,
# and the certificate is validated over HTTP through it, so the CNAME is
# both the routing and the domain-ownership check.
#
# The distribution serves requests exactly as the default hosts' one does:
# the same origin, origin secret, policies, host function and WAF.

resource "aws_cloudfront_connection_group" "tenants" {
  name         = "${var.name_prefix}-custom-hosts"
  enabled      = true
  ipv6_enabled = true
}

resource "aws_cloudfront_multitenant_distribution" "tenants" {
  enabled      = true
  comment      = "${var.name_prefix} custom login hosts"
  web_acl_id   = aws_wafv2_web_acl.this.arn
  http_version = "http2and3"

  origin {
    id          = "auth"
    domain_name = local.origin_domain
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
      origin_read_timeout    = 30
    }
    custom_header {
      header_name  = "X-Litelogin-Origin-Secret"
      header_value = random_password.origin[var.active_origin_secret].result
    }
  }

  default_cache_behavior {
    target_origin_id         = "auth"
    viewer_protocol_policy   = "redirect-to-https"
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.auth.id
    compress                 = true
    allowed_methods {
      items          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
      cached_methods = ["GET", "HEAD"]
    }
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.host.arn
    }
  }

  dynamic "cache_behavior" {
    for_each = ["/token", "/userinfo"]
    content {
      path_pattern             = cache_behavior.value
      target_origin_id         = "auth"
      viewer_protocol_policy   = "https-only"
      cache_policy_id          = aws_cloudfront_cache_policy.api.id
      origin_request_policy_id = aws_cloudfront_origin_request_policy.api.id
      compress                 = true
      allowed_methods {
        items          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
        cached_methods = ["GET", "HEAD"]
      }
      function_association {
        event_type   = "viewer-request"
        function_arn = aws_cloudfront_function.host.arn
      }
    }
  }

  cache_behavior {
    path_pattern           = "/.well-known/*"
    target_origin_id       = "auth"
    viewer_protocol_policy = "redirect-to-https"
    cache_policy_id        = aws_cloudfront_cache_policy.well_known.id
    compress               = true
    allowed_methods {
      items          = ["GET", "HEAD", "OPTIONS"]
      cached_methods = ["GET", "HEAD"]
    }
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

  # Tenants take no parameters: each is just a host.
  tenant_config {}

  # Each tenant brings its own managed certificate.
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

output "tenant_distribution_id" {
  description = "The multi-tenant distribution custom hosts are tenants of."
  value       = aws_cloudfront_multitenant_distribution.tenants.id
}

output "tenant_distribution_arn" {
  value = aws_cloudfront_multitenant_distribution.tenants.arn
}

output "connection_group_id" {
  value = aws_cloudfront_connection_group.tenants.id
}

output "connection_group_arn" {
  value = aws_cloudfront_connection_group.tenants.arn
}

output "routing_endpoint" {
  description = "Where custom hosts' CNAME records point."
  value       = aws_cloudfront_connection_group.tenants.routing_endpoint
}
