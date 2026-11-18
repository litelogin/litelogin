# Customer managed key for encrypting the DynamoDB tables, when
# table_encryption = "customer-managed", and the key that encrypts users'
# TOTP secrets (two-factor sign-in), always.
#
# Token signing keys are not created here: the key rotation Lambda creates
# them at runtime (see "Rotate signing keys" in Datamodel.md).

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "name_prefix" {
  description = "Prefix for resource names, e.g. litelogin-dev."
  type        = string
}

variable "create" {
  description = "Create the table key."
  type        = bool
  default     = true
}

resource "aws_kms_key" "tables" {
  count                   = var.create ? 1 : 0
  description             = "${var.name_prefix} DynamoDB table encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "tables" {
  count         = var.create ? 1 : 0
  name          = "alias/${var.name_prefix}-tables"
  target_key_id = aws_kms_key.tables[0].key_id
}

# TOTP secrets are the one credential the Auth Lambda must read back, so
# they can't be stored hashed. Each is encrypted with this key, bound to its
# user by the encryption context; only the Auth Lambda may use it. Deleting
# the key makes every user's authenticator app stop working.
resource "aws_kms_key" "mfa" {
  description             = "${var.name_prefix} TOTP secrets (two-factor sign-in)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "mfa" {
  name          = "alias/${var.name_prefix}-mfa"
  target_key_id = aws_kms_key.mfa.key_id
}

# Identity providers' secrets (an org's client secrets and Apple keys for
# social sign-in) must be read back, so they're encrypted with this key,
# bound to their pool and provider by the encryption context. The Admin
# Lambda may only encrypt with it and the Auth Lambda only decrypt.
# Deleting the key makes every provider's secrets unusable: they'd have to
# be set again.
resource "aws_kms_key" "idp" {
  description             = "${var.name_prefix} identity provider secrets (social sign-in)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "idp" {
  name          = "alias/${var.name_prefix}-idp"
  target_key_id = aws_kms_key.idp.key_id
}

# Before table_encryption, the key always existed.
moved {
  from = aws_kms_key.tables
  to   = aws_kms_key.tables[0]
}

moved {
  from = aws_kms_alias.tables
  to   = aws_kms_alias.tables[0]
}

output "tables_key_arn" {
  description = "The key's ARN, or null if there is none."
  value       = one(aws_kms_key.tables[*].arn)
}

output "mfa_key_arn" {
  description = "The ARN of the key that encrypts TOTP secrets."
  value       = aws_kms_key.mfa.arn
}

output "idp_key_arn" {
  description = "The ARN of the key that encrypts identity providers' secrets."
  value       = aws_kms_key.idp.arn
}
