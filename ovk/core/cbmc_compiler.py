"""Honest CBMC obligation registration for adapter paths.

Does not claim project-grounded strict eligibility unless harnesses include
project code and function targets are present.
"""

from __future__ import annotations

from typing import Any

from ovk.core.bundle import content_digest
from ovk.core.compiler_bridge import register_cbmc_project
from ovk.core.execution_models import (
    VerificationObligation,
    compute_abstraction_digest,
    compute_obligation_id,
)
from ovk.core.materials import material_reference_from_payload
from ovk.core.models import RiskSeverity, VerificationSubject

COMPILER_VERSION = "0.1.0"


def compile_cbmc_obligation(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
    policy_digest: str | None = None,
) -> VerificationObligation:
    """Register CBMC materials as a typed obligation with honest guarantees."""
    project, coverage, compiler_id = register_cbmc_project(data)
    guarantee = project.guarantee_type
    abstraction = {
        "kind": "cbmc_project",
        "input": data,
        "cbmc_project": project.model_dump(mode="json"),
        "source_compiler": compiler_id,
        "guarantee_type": guarantee,
        "project_grounded": guarantee == "bounded_project_model_check",
    }
    materials = [
        material_reference_from_payload(
            material_id=content_digest({"cbmc": compiler_id})[:32],
            kind="generated_harness" if project.harnesses else "source_file",
            uri=f"ovk-material:cbmc/{compiler_id}",
            payload=project.model_dump(mode="json"),
            source_revision=head_sha,
        )
    ]
    provisional = VerificationObligation(
        obligation_id="pending",
        subject=VerificationSubject(repo=repo, head_sha=head_sha, base_sha=base_sha),
        intent_id=str(data.get("intent_id") or "cbmc-bounded-check"),
        intent_version="0.1.0",
        lane="cbmc",
        property_kind="safety",
        severity=RiskSeverity.HIGH,
        compiler_id=compiler_id,
        compiler_version=COMPILER_VERSION,
        materials=materials,
        abstraction=abstraction,
        abstraction_digest=compute_abstraction_digest(abstraction),
        coverage=coverage,
        acceptable_guarantees=[guarantee],
        required_capabilities=["cbmc"],
        policy_digest=policy_digest or content_digest({"lane": "cbmc"}),
    )
    return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})
