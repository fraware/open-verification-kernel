# Verification Intent Templates

Templates are reusable engineering obligations that OVK can apply to agent-authored or human-authored changes.

A template should be backend-neutral. It describes what must remain true, expected failure modes, acceptable evidence classes, and merge policy. The router later chooses OPA, Z3, Kani, TLA+, Dafny, Verus, Lean, Cedar, CBMC, Alloy, or another backend.

## Initial templates

| Template | Domain | Risk | First backend |
|---|---|---|---|
| `ci_cd/agent_cannot_disable_own_gate.intent.json` | CI/CD and agent authority | critical | OPA/static policy |
| `authorization/no_admin_route_bypass.intent.json` | Authorization | high | Z3/OPA |
| `infrastructure/no_public_sensitive_resource.intent.json` | Infrastructure | high | OPA/Z3 graph |

## Template requirements

Each template should include:

- `intent_id`
- domain
- scope
- actor and resource shape
- property kind
- natural-language invariant
- formal hint
- failure modes
- acceptable evidence classes
- risk
- merge policy
- anti-vacuity guidance for high-risk templates
