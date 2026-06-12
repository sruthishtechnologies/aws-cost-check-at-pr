package terraform.tags

required_tags := {
  "Environment",
  "Owner",
  "CostCenter"
}

deny[msg] {
  resource := input.resource_changes[_]

  tag := required_tags[_]

  not resource.change.after.tags[tag]

  msg := sprintf(
    "%s missing tag %s",
    [resource.address, tag]
  )
}
