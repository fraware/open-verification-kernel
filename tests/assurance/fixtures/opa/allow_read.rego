package ovk.assurance

default allow = false

allow {
  input.action == "read"
}

violation[msg] {
  not allow
  msg := sprintf("action %v not allowed", [input.action])
}
