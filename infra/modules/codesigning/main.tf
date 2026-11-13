# Code signing for an environment's Lambda functions (Architecture.md,
# "Supply chain"): an AWS Signer profile, a versioned bucket for the
# packages, and a code signing configuration that makes Lambda reject any
# code the profile didn't sign.
#
# The Lambda module (code_signing) uploads each package, signs it with a
# Signer job and deploys the signed copy. With the configuration attached,
# an UpdateFunctionCode call with unsigned or otherwise-signed code fails,
# whoever makes it, so changing what runs needs signer:StartSigningJob on
# this profile as well as Lambda access.

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

data "aws_caller_identity" "current" {}

# Profile names allow only letters, digits and underscores. A destroyed
# profile is only canceled, and its name can never be used again, so each
# profile gets a unique suffix: an environment can be removed and created
# again in the same account. Changing to unique names replaces the profile
# of a deployment made before (litelogin_<environment>_lambda) once.
resource "aws_signer_signing_profile" "lambda" {
  name_prefix = "${replace(var.name_prefix, "-", "_")}_lambda_"
  platform_id = "AWSLambda-SHA384-ECDSA"

  signature_validity_period {
    value = 5
    type  = "YEARS"
  }

  # When the profile is replaced, the code signing configuration and the
  # functions move to the new one before the old one is canceled.
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lambda_code_signing_config" "this" {
  description = "${var.name_prefix}: only code signed by ${aws_signer_signing_profile.lambda.name}"

  allowed_publishers {
    signing_profile_version_arns = [aws_signer_signing_profile.lambda.version_arn]
  }

  policies {
    untrusted_artifact_on_deployment = "Enforce"
  }
}

# Signer jobs read a specific object version, so the bucket is versioned.
resource "aws_s3_bucket" "packages" {
  bucket        = "${var.name_prefix}-lambda-packages-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "packages" {
  bucket = aws_s3_bucket.packages.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "packages" {
  bucket                  = aws_s3_bucket.packages.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "packages" {
  bucket = aws_s3_bucket.packages.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "packages" {
  bucket = aws_s3_bucket.packages.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "TLSOnly"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.packages.arn, "${aws_s3_bucket.packages.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.packages]
}

# Functions keep running from their own copy of the code, so old packages
# can go; keep a few months for rollbacks.
resource "aws_s3_bucket_lifecycle_configuration" "packages" {
  bucket = aws_s3_bucket.packages.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = 180
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
  depends_on = [aws_s3_bucket_versioning.packages]
}

output "code_signing" {
  description = "Pass to the Lambda module's code_signing."
  value = {
    bucket       = aws_s3_bucket.packages.id
    profile_name = aws_signer_signing_profile.lambda.name
    config_arn   = aws_lambda_code_signing_config.this.arn
  }
  depends_on = [aws_s3_bucket_versioning.packages, aws_s3_bucket_policy.packages]
}
