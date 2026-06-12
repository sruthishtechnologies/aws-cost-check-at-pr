package kubernetes.cis

# Block root user
deny[msg] {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]

  not container.securityContext.runAsNonRoot

  msg := sprintf(
    "Container %s must run as non-root",
    [container.name]
  )
}

# Block privilege escalation
deny[msg] {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]

  not container.securityContext.allowPrivilegeEscalation == false

  msg := sprintf(
    "Container %s allows privilege escalation",
    [container.name]
  )
}

# Enforce read-only root filesystem
deny[msg] {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]

  not container.securityContext.readOnlyRootFilesystem

  msg := sprintf(
    "Container %s must use readOnlyRootFilesystem",
    [container.name]
  )
}

# Block hostNetwork
deny[msg] {
  input.kind == "Deployment"

  input.spec.template.spec.hostNetwork == true

  msg := "hostNetwork is not allowed"
}

# Block hostPID
deny[msg] {
  input.kind == "Deployment"

  input.spec.template.spec.hostPID == true

  msg := "hostPID is not allowed"
}

# Block hostIPC
deny[msg] {
  input.kind == "Deployment"

  input.spec.template.spec.hostIPC == true

  msg := "hostIPC is not allowed"
}

# Restrict hostPath volumes
deny[msg] {
  input.kind == "Deployment"

  volume := input.spec.template.spec.volumes[_]

  volume.hostPath

  msg := sprintf(
    "hostPath volume %s is not allowed",
    [volume.name]
  )
}
