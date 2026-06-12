package terraform.tags

deny[msg] {
  resource := input.resource_changes[_]
  resource.mode == "managed"

  not resource.change.after.tags.Environment

  msg := sprintf("%s missing Environment tag", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.mode == "managed"

  not resource.change.after.tags.CostCenter

  msg := sprintf("%s missing CostCenter tag", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.mode == "managed"

  not resource.change.after.tags.Owner

  msg := sprintf("%s missing Owner tag", [resource.address])
}
