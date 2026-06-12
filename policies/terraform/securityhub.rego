# Block public security groups
package terraform.securityhub

deny[msg] {
  resource := input.resource_changes[_]

  resource.type == "aws_security_group_rule"

  resource.change.after.type == "ingress"

  resource.change.after.cidr_blocks[_] == "0.0.0.0/0"

  msg := sprintf(
    "%s allows public access",
    [resource.address]
  )
}

# Enforce EBS encryption
deny[msg] {
  resource := input.resource_changes[_]

  resource.type == "aws_ebs_volume"

  not resource.change.after.encrypted

  msg := sprintf(
    "%s EBS encryption disabled",
    [resource.address]
  )
}

# Enforce RDS encryption
deny[msg] {
  resource := input.resource_changes[_]

  resource.type == "aws_db_instance"

  not resource.change.after.storage_encrypted

  msg := sprintf(
    "%s RDS encryption disabled",
    [resource.address]
  )
}

# Enforce S3 encryption
deny[msg] {
  resource := input.resource_changes[_]

  resource.type == "aws_s3_bucket"

  msg := sprintf(
    "%s must use S3 encryption",
    [resource.address]
  )
}
