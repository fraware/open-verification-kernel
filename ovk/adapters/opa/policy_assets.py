"""OPA policy asset generation for self-protection.

This module stores the first Rego policy as data so engineers can materialize it
for real OPA CLI execution in Sprint 2 without changing the evidence semantics.
The deterministic Python evaluator remains the fixture oracle.
"""

from __future__ import annotations

from pathlib import Path


SELF_PROTECTION_REGO = r'''
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
'''.strip() + "\n"


def write_self_protection_rego(path: Path) -> None:
    """Write the self-protection Rego policy to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SELF_PROTECTION_REGO, encoding="utf-8")


def write_infra_exposure_rego(path: Path) -> None:
    """Write the infrastructure exposure Rego policy to disk."""
    from ovk.adapters.opa.infra_exposure import INFRA_EXPOSURE_REGO

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(INFRA_EXPOSURE_REGO, encoding="utf-8")


def resolve_self_protection_policy_path() -> Path:
    """Return a usable Rego policy path, preferring packaged assets then writing a temp copy."""
    candidates = [
        Path("adapters/opa/policies/self_protection.rego"),
        Path("ovk/package_data/adapters/opa/policies/self_protection.rego"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    from ovk.paths import ovk_data_root

    packaged = ovk_data_root() / "adapters" / "opa" / "policies" / "self_protection.rego"
    if packaged.exists():
        return packaged.resolve()
    fallback = Path(".verification") / "generated_policies" / "self_protection.rego"
    write_self_protection_rego(fallback)
    return fallback.resolve()
