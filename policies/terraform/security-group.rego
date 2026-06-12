package terraform.security

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group_rule"

  resource.change.after.type == "ingress"
  resource.change.after.from_port == 22
  resource.change.after.cidr_blocks[_] == "0.0.0.0/0"

  msg := sprintf("%s allows SSH from public internet", [resource.address])
}
