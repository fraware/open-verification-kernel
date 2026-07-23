package ovk.self_protection

after_has_gate(gate) {
  input.after.required_checks[_] == gate
}

violation[msg] {
  input.actor.type == "ai_agent"
  gate := input.ovk_gate_name
  input.before.required_checks[_] == gate
  not after_has_gate(gate)
  msg := sprintf("required verification gate removed: %s", [gate])
}

violation[msg] {
  input.actor.type == "ai_agent"
  path := input.changed_files[_]
  startswith(path, ".verification/")
  msg := sprintf("verification configuration changed: %s", [path])
}

violation[msg] {
  input.actor.type == "ai_agent"
  input.before.workflow_permissions.actions != "write"
  input.after.workflow_permissions.actions == "write"
  msg := "workflow actions permission escalated to write"
}
