# Transactional email through SES: the domain identity with Easy DKIM, a
# custom MAIL FROM domain (so SPF aligns for DMARC), DMARC, and a
# configuration set that suppresses addresses that bounce or complain.
#
# A new account's SES is in the sandbox: it only delivers to verified
# addresses. Verify a test recipient outside Terraform (it's a one-off,
# personal address): aws sesv2 create-email-identity --email-identity <you>.
# Production access is requested from AWS separately.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "name_prefix" {
  type = string
}

variable "domain" {
  description = "Sending domain, e.g. dev.litelogin.com."
  type        = string
}

variable "zone_id" {
  description = "Route 53 zone of domain."
  type        = string
}

data "aws_region" "current" {}

locals {
  mail_from = "mail.${var.domain}"
}

resource "aws_sesv2_configuration_set" "this" {
  configuration_set_name = "${var.name_prefix}-transactional"

  delivery_options {
    tls_policy = "REQUIRE"
  }
  reputation_options {
    reputation_metrics_enabled = true
  }
  sending_options {
    sending_enabled = true
  }
  suppression_options {
    suppressed_reasons = ["BOUNCE", "COMPLAINT"]
  }
}

resource "aws_sesv2_email_identity" "domain" {
  email_identity         = var.domain
  configuration_set_name = aws_sesv2_configuration_set.this.configuration_set_name
  dkim_signing_attributes {
    next_signing_key_length = "RSA_2048_BIT"
  }
}

resource "aws_route53_record" "dkim" {
  count   = 3
  zone_id = var.zone_id
  name    = "${aws_sesv2_email_identity.domain.dkim_signing_attributes[0].tokens[count.index]}._domainkey.${var.domain}"
  type    = "CNAME"
  ttl     = 1800
  records = ["${aws_sesv2_email_identity.domain.dkim_signing_attributes[0].tokens[count.index]}.dkim.amazonses.com"]
}

resource "aws_sesv2_email_identity_mail_from_attributes" "domain" {
  email_identity         = aws_sesv2_email_identity.domain.email_identity
  mail_from_domain       = local.mail_from
  behavior_on_mx_failure = "USE_DEFAULT_VALUE"
}

resource "aws_route53_record" "mail_from_mx" {
  zone_id = var.zone_id
  name    = local.mail_from
  type    = "MX"
  ttl     = 1800
  records = ["10 feedback-smtp.${data.aws_region.current.region}.amazonses.com"]
}

resource "aws_route53_record" "mail_from_spf" {
  zone_id = var.zone_id
  name    = local.mail_from
  type    = "TXT"
  ttl     = 1800
  records = ["v=spf1 include:amazonses.com -all"]
}

resource "aws_route53_record" "dmarc" {
  zone_id = var.zone_id
  name    = "_dmarc.${var.domain}"
  type    = "TXT"
  ttl     = 1800
  records = ["v=DMARC1; p=quarantine; adkim=s; aspf=s"]
}

output "from_address" {
  value = "no-reply@${var.domain}"
}

output "configuration_set_name" {
  value = aws_sesv2_configuration_set.this.configuration_set_name
}

output "configuration_set_arn" {
  value = aws_sesv2_configuration_set.this.arn
}
