package ovk.self_protection

violation[msg] {
  input.actor.type == "ai_agent"
  gate := input.ovk_gate_name
  input.before.required_checks[_] == gate
  not input.after.required_checks[_] == gate
  msg := sprintf("required verification gate removed: %s", [gate])
}

violation[msg] {
  input.actor.type == "ai_agent"
  some path
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
