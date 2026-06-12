package kubernetes.security

# 1. Require CPU and memory limits
deny[msg] {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]

  not container.resources.limits.cpu

  msg := sprintf("Container %s is missing CPU limit", [container.name])
}

deny[msg] {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]

  not container.resources.limits.memory

  msg := sprintf("Container %s is missing memory limit", [container.name])
}

deny[msg] {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]

  not container.resources.requests.cpu

  msg := sprintf("Container %s is missing CPU request", [container.name])
}

deny[msg] {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]

  not container.resources.requests.memory

  msg := sprintf("Container %s is missing memory request", [container.name])
}

# 2. Block privileged containers
deny[msg] {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]

  container.securityContext.privileged == true

  msg := sprintf("Container %s is running as privileged", [container.name])
}

# 3. Block latest image tag
deny[msg] {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]

  endswith(container.image, ":latest")

  msg := sprintf("Container %s uses latest image tag", [container.name])
}

deny[msg] {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]

  not contains(container.image, ":")

  msg := sprintf("Container %s image tag is missing", [container.name])
}
