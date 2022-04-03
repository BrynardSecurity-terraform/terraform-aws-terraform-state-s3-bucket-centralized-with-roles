resource "aws_s3_bucket" "this" {
  bucket = "${var.name_prefix}-remote-state-backend${var.name_suffix}"

  tags   = var.input_tags
}

resource "aws_s3_bucket_logging" "this" {
  bucket  = aws_s3_bucket.this.id
  target_bucket = var.log_bucket_id
  target_prefix = "s3/${var.name_prefix}-remote-state-backend${var.name_suffix}/"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.remote_state_backend.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_iam_policy_document" "encrypted_transit_bucket_policy" {
  statement {
    actions = [
      "s3:*"
    ]
    condition {
      test = "Bool"
      values = [
        "false"
      ]
      variable = "aws:SecureTransport"
    }
    effect = "Deny"
    principals {
      identifiers = [
        "*"
      ]
      type = "AWS"
    }
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    sid = "DenyUnsecuredTransport"
  }
  statement {
    actions = [
      "s3:PutObject"
    ]
    condition {
      test = "StringNotEquals"
      values = [
        "aws:kms"
      ]
      variable = "s3:x-amz-server-side-encryption"
    }
    effect = "Deny"
    principals {
      identifiers = [
        "*"
      ]
      type = "AWS"
    }
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    sid = "DenyIncorrectEncryptionHeader"
  }
  statement {
    actions = [
      "s3:PutObject"
    ]
    condition {
      test = "Null"
      values = [
        "true"
      ]
      variable = "s3:x-amz-server-side-encryption"
    }
    effect = "Deny"
    principals {
      identifiers = [
        "*"
      ]
      type = "AWS"
    }
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    sid = "DenyUnencryptedObjectUploads"
  }
  statement {
    actions = [
      "s3:PutObject"
    ]
    condition {
      test = "StringNotEquals"
      values = [
        "bucket-owner-full-control"
      ]
      variable = "s3:x-amz-acl"
    }
    effect = "Deny"
    principals {
      identifiers = [
        "*"
      ]
      type = "AWS"
    }
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    sid = "RequireBucketOwnerACL"
  }
}

resource "aws_s3_bucket_policy" "remote_state_backend" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.encrypted_transit_bucket_policy.json
}
