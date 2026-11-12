# The Route 53 hosted zone for an environment's default host domain, e.g.
# login.example.com. The parent domain's DNS delegates to it with NS
# records for the domain, pointing to name_servers.
#
# Terraform manages every record in this zone: the wildcard certificate's
# validation, the default hosts' alias to CloudFront, and SES DKIM.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "domain" {
  description = "The domain to host, e.g. login.example.com."
  type        = string
}

resource "aws_route53_zone" "this" {
  name    = var.domain
  comment = "LiteLogin default login hosts and email (delegated from the parent domain)"
}

output "zone_id" {
  value = aws_route53_zone.this.zone_id
}

output "name_servers" {
  description = "Add these as NS records for the domain at the parent domain's DNS provider."
  value       = aws_route53_zone.this.name_servers
}
