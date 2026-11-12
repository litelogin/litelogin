# The Config and Session tables described in Datamodel.md.
#
# Key, index and projection names must match internal/store/schema.go.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "name_prefix" {
  description = "Prefix for table names, e.g. litelogin-dev."
  type        = string
}

variable "kms_key_arn" {
  description = "Customer managed KMS key used to encrypt both tables."
  type        = string
}

variable "deletion_protection" {
  description = "Protect both tables from deletion. Disable only for throwaway environments."
  type        = bool
  default     = true
}

variable "session_point_in_time_recovery" {
  description = "Enable point-in-time recovery on the Session table. Restoring stale sessions has little value, so this is off by default."
  type        = bool
  default     = false
}

resource "aws_dynamodb_table" "config" {
  name                        = "${var.name_prefix}-config"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "PK"
  range_key                   = "SK"
  deletion_protection_enabled = var.deletion_protection

  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "PK"
    type = "S"
  }
  attribute {
    name = "SK"
    type = "S"
  }
  attribute {
    name = "GSI1PK"
    type = "S"
  }
  attribute {
    name = "GSI1SK"
    type = "S"
  }
  attribute {
    name = "GSI2PK"
    type = "S"
  }
  attribute {
    name = "GSI2SK"
    type = "S"
  }

  # Pool -> users, sorted by email.
  global_secondary_index {
    name = "GSI1"
    key_schema {
      attribute_name = "GSI1PK"
      key_type       = "HASH"
    }
    key_schema {
      attribute_name = "GSI1SK"
      key_type       = "RANGE"
    }
    projection_type    = "INCLUDE"
    non_key_attributes = ["email", "email_verified", "status", "created_at"]
  }

  # Outstanding background work, read by the reconciler.
  global_secondary_index {
    name = "GSI2"
    key_schema {
      attribute_name = "GSI2PK"
      key_type       = "HASH"
    }
    key_schema {
      attribute_name = "GSI2SK"
      key_type       = "RANGE"
    }
    projection_type    = "INCLUDE"
    non_key_attributes = ["status", "work_attempts", "work_updated_at", "work_last_error"]
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }
}

resource "aws_dynamodb_table" "session" {
  name                        = "${var.name_prefix}-session"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "PK"
  range_key                   = "SK"
  deletion_protection_enabled = var.deletion_protection

  attribute {
    name = "PK"
    type = "S"
  }
  attribute {
    name = "SK"
    type = "S"
  }
  attribute {
    name = "GSI1PK"
    type = "S"
  }
  attribute {
    name = "GSI1SK"
    type = "S"
  }

  # User -> sessions and refresh families. Listing and cleanup only.
  global_secondary_index {
    name = "GSI1"
    key_schema {
      attribute_name = "GSI1PK"
      key_type       = "HASH"
    }
    key_schema {
      attribute_name = "GSI1SK"
      key_type       = "RANGE"
    }
    projection_type    = "INCLUDE"
    non_key_attributes = ["client_id", "auth_version", "created_at", "last_seen_at", "ip", "user_agent", "expires_at"]
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = var.session_point_in_time_recovery
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }
}

output "config_table_name" {
  value = aws_dynamodb_table.config.name
}

output "config_table_arn" {
  value = aws_dynamodb_table.config.arn
}

output "config_stream_arn" {
  value = aws_dynamodb_table.config.stream_arn
}

output "session_table_name" {
  value = aws_dynamodb_table.session.name
}

output "session_table_arn" {
  value = aws_dynamodb_table.session.arn
}
