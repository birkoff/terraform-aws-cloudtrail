  
terraform {
  required_version = ">= 0.11.13"

  backend "remote" {
    hostname     = "app.terraform.io"
    organization = "MyOrg"

    workspaces {
      name = "cloudtrail"
    }
  }
}

provider "aws" {
  region = "${var.region}"  
}

variable "bucket" {
  default = "${var.bucket}"  
}

variable "region" {
}

resource "aws_cloudtrail" "cloudtrail" {
  name                          = "cloudtrail"
  s3_bucket_name                = "${aws_s3_bucket.cloudtrail.id}"
  s3_key_prefix                 = "organizations"
  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = true

  cloud_watch_logs_role_arn     = "${aws_iam_role.cloudtrail-logs-role.arn}"
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail-logs.arn}"

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda"]
    }
  }
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "${var.bucket}"
  force_destroy = true

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": ["arn:aws:s3:::${var.bucket}"]
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": [
              "arn:aws:s3:::${var.bucket}/*"
            ],
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}

resource "aws_cloudwatch_log_group" "cloudtrail-logs" {
  name = "cloudtrail-logs"

  tags = {
    Environment = "prod"
    Application = "cloudtrail"
  }
}

resource "aws_iam_role" "cloudtrail-logs-role" {
  name = "cloudtrail-logs-role"
  path = "/"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "cloudtrail-logs-policy" {
  name = "cloudtrail-logs-policy"
  role = "${aws_iam_role.cloudtrail-logs-role.id}"

  policy = <<EOP
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "s3:PutBucketAcl",
                "s3:List*",
                "s3:Get*",
                "cloudwatch:PutMetricData"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}
EOP
}
