# Customer managed key for encrypting the DynamoDB tables, when
# table_encryption = "customer-managed".
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
