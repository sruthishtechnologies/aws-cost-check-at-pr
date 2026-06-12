package terraform.region

approved_regions := {
  "us-east-1",
  "us-west-2",
  "ap-south-1",
  "ap-south-2"
}

deny[msg] {
  region := input.configuration.provider_config.aws.expressions.region.constant_value

  not approved_regions[region]

  msg := sprintf(
    "Region %s not approved",
    [region]
  )
}
