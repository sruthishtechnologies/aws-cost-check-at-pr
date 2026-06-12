package terraform.security

# 1. Enforce S3 encryption
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  resource.change.actions[_] != "delete"

  bucket_name := resource.change.after.bucket

  not s3_encryption_exists(bucket_name)

  msg := sprintf("%s is missing S3 server-side encryption", [resource.address])
}

s3_encryption_exists(bucket_name) {
  enc := input.resource_changes[_]
  enc.type == "aws_s3_bucket_server_side_encryption_configuration"
  enc.change.after.bucket == bucket_name
}

# 2. Enforce EBS encryption
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ebs_volume"
  resource.change.actions[_] != "delete"

  not resource.change.after.encrypted

  msg := sprintf("%s EBS volume encryption is not enabled", [resource.address])
}

# 3. Enforce RDS encryption
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_db_instance"
  resource.change.actions[_] != "delete"

  not resource.change.after.storage_encrypted

  msg := sprintf("%s RDS encryption is not enabled", [resource.address])
}

# 4. Block unsupported AWS regions
approved_regions := {
  "us-east-1",
  "us-west-2",
  "ap-south-1"
}

deny[msg] {
  resource := input.configuration.provider_config.aws.expressions.region.constant_value

  not approved_regions[resource]

  msg := sprintf("Unsupported AWS region used: %s", [resource])
}

# 5. Require RDS backup
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_db_instance"
  resource.change.actions[_] != "delete"

  resource.change.after.backup_retention_period < 7

  msg := sprintf("%s RDS backup retention must be at least 7 days", [resource.address])
}

# 6. Block public S3 access
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.actions[_] != "delete"

  resource.change.after.block_public_acls == false

  msg := sprintf("%s must block public ACLs", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.actions[_] != "delete"

  resource.change.after.block_public_policy == false

  msg := sprintf("%s must block public bucket policy", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.actions[_] != "delete"

  resource.change.after.ignore_public_acls == false

  msg := sprintf("%s must ignore public ACLs", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.actions[_] != "delete"

  resource.change.after.restrict_public_buckets == false

  msg := sprintf("%s must restrict public buckets", [resource.address])
}
