package terraform.ec2

approved_instance_types := {
  "t3.micro",
  "t3.small",
  "t3.medium"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"

  not approved_instance_types[resource.change.after.instance_type]

  msg := sprintf(
    "%s uses unapproved instance type: %s",
    [resource.address, resource.change.after.instance_type]
  )
}
