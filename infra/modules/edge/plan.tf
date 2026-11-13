# CloudFront's Free flat-rate plan (free_plan): the default hosts'
# distribution, its web ACL and the domain's Route 53 zone, at no charge
# for up to 1 million requests a month (Cost.md, "CloudFront flat-rate
# plans"). Cancelling it (free_plan = false) takes effect at once.
#
# A plan covers one distribution, whose web ACL and CloudFront Function no
# other distribution may use: so no custom hosts, whose distribution
# shares them. Its web ACL may have no rule that matches paths, labels or
# IP sets: so no rate-limit exemptions, which are a scope-down. And the
# distribution may use only AWS managed cache and origin request policies
# (main.tf).

# Cancelling returns at once, but CloudFront and WAF refuse the rules and
# policies the plan doesn't allow until the cancellation has settled,
# which took under a minute in testing. Turning the plan off destroys the
# subscription, then this (which waits), then puts them back.
resource "time_sleep" "plan_cancelled" {
  count            = var.free_plan ? 1 : 0
  destroy_duration = "3m"
  triggers = {
    distribution = aws_cloudfront_distribution.this.arn
    web_acl      = aws_wafv2_web_acl.this.arn
  }
}

resource "aws_pricingplanmanager_subscription" "free" {
  count = var.free_plan ? 1 : 0

  plan_family = "CloudFront"
  plan_tier   = "FREE"
  resource_arns = [
    time_sleep.plan_cancelled[0].triggers.distribution,
    time_sleep.plan_cancelled[0].triggers.web_acl,
    "arn:aws:route53:::hostedzone/${var.zone_id}",
  ]

  lifecycle {
    precondition {
      condition     = !var.custom_hosts
      error_message = "cloudfront_plan = \"free\" needs custom_hosts = false: the custom hosts' distribution shares the web ACL and host function, which a plan doesn't allow."
    }
    precondition {
      condition     = length(var.rate_limit_exempt_cidrs) == 0
      error_message = "cloudfront_plan = \"free\" allows no rate_limit_exempt_cidrs: its web ACL can't have a scope-down statement. Use cloudfront_plan = \"pay-as-you-go\" for a load test."
    }
  }
}

output "free_plan_subscription" {
  description = "The Free plan subscription's ARN and status, or null without it."
  value = var.free_plan ? {
    arn    = aws_pricingplanmanager_subscription.free[0].arn
    status = aws_pricingplanmanager_subscription.free[0].status
  } : null
}
