"""OPA Rego policy evaluation for infrastructure exposure (domain pack #2)."""

from __future__ import annotations

from typing import Any

from ovk.adapters.external.stub import evaluate_with_optional_binary
from ovk.adapters.infra.exposure import find_exposure_counterexamples
from ovk.core.models import VerificationEvidence


INFRA_EXPOSURE_REGO = r'''
package ovk.infra_exposure

violation[msg] {
  some resource
  resource := input.resources[_]
  resource.sensitivity == "confidential"
  resource.public_exposure == true
  msg := sprintf("sensitive resource publicly exposed: %s", [resource.resource_id])
}

violation[msg] {
  some resource
  resource := input.resources[_]
  resource.sensitivity == "restricted"
  resource.public_exposure == true
  msg := sprintf("sensitive resource publicly exposed: %s", [resource.resource_id])
}
'''.strip() + "\n"


def _deterministic_infra_opa(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    counterexamples = find_exposure_counterexamples(data)
    if counterexamples:
        return "fail", counterexamples
    if not data.get("resources"):
        return "unknown", [{"summary": "resources must be a non-empty list", "failure_mode": "infrastructure_abstraction_invalid"}]
    return "pass", []


def evaluate_infra_exposure_opa(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
) -> VerificationEvidence:
    """Evaluate infrastructure exposure using the OPA infra Rego domain pack."""
    return evaluate_with_optional_binary(
        backend_name="opa",
        binary_name="opa",
        data={**data, "intent_id": data.get("intent_id", "no-public-sensitive-resource")},
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        deterministic_evaluator=_deterministic_infra_opa,
        assumptions=[
            "OPA infra domain pack encodes public exposure of sensitive resources.",
            "Deterministic oracle mirrors Rego policy semantics when OPA is unavailable.",
        ],
        limits=["Does not verify runtime cloud API behavior beyond supplied resource abstraction."],
    )


def write_infra_exposure_rego(path: Any) -> None:
    """Materialize the infrastructure exposure Rego policy to disk."""
    from pathlib import Path

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(INFRA_EXPOSURE_REGO, encoding="utf-8")
