# Customer managed key for encrypting the DynamoDB tables.
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

resource "aws_kms_key" "tables" {
  description             = "${var.name_prefix} DynamoDB table encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "tables" {
  name          = "alias/${var.name_prefix}-tables"
  target_key_id = aws_kms_key.tables.key_id
}

output "tables_key_arn" {
  value = aws_kms_key.tables.arn
}
