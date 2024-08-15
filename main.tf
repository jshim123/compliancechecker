provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "example" {
  name = "example-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = [
            "config.amazonaws.com",
            "cloudtrail.amazonaws.com",
            "guardduty.amazonaws.com",
          ]
        },
        Effect = "Allow",
        Sid    = "",
      },
    ],
  })
}

resource "aws_iam_role_policy" "example" {
  name   = "example-policy"
  role   = aws_iam_role.example.name
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "cloudtrail:CreateTrail",
          "cloudtrail:DescribeTrails",
          "cloudtrail:StartLogging",
          "cloudtrail:StopLogging",
          "guardduty:CreateDetector",
          "guardduty:ListDetectors",
          "config:PutConfigurationRecorder",
          "config:DescribeConfigurationRecorders",
          "config:StartConfigurationRecorder",
          "config:StopConfigurationRecorder",
          "cloudwatch:PutMetricData",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
        ],
        Resource = "*"
      }
    ],
  })
}

resource "aws_cloudwatch_log_group" "group" {
  name = "group"
}

resource "aws_cloudwatch_log_stream" "example" {
  name           = "example"
  log_group_name = aws_cloudwatch_log_group.example.name
}

data "aws_caller_identity" "current" {}

data "aws_s3_bucket" "compliance_checker" {
  bucket = "compliance-checker-jshim123"
}

output "s3_bucket_name" {
  value = data.aws_s3_bucket.compliance_checker.bucket
}