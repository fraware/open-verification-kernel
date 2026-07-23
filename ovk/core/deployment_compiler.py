"""Backend-neutral deployment obligation compiler."""

from __future__ import annotations

from typing import Any

from ovk.core.bundle import content_digest
from ovk.core.compiler_bridge import (
    compile_deployment_ir,
    deployment_coverage,
    material_refs_from_digest,
)
from ovk.core.execution_models import (
    AbstractionCoverage,
    MaterialReference,
    VerificationObligation,
    compute_abstraction_digest,
    compute_obligation_id,
)
from ovk.core.models import RiskSeverity, VerificationSubject

COMPILER_ID = "ovk.deployment.neutral.v1"
COMPILER_VERSION = "0.2.0"


def compile_deployment_obligation(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
    policy_digest: str | None = None,
    policy: dict[str, Any] | None = None,
) -> VerificationObligation:
    """Compile a backend-neutral deployment approval-state obligation.

    Uses GitHub Environments, Argo Rollouts, or explicit schema compilers when
    their materials are present.
    """
    source = compile_deployment_ir(data)
    if source is not None:
        ir, compiler_id = source
        lane_input = ir.to_lane_input()
        for key in ("author_type", "agent", "task"):
            if key in data:
                lane_input[key] = data[key]
        coverage = deployment_coverage(ir)
        materials = [
            material_refs_from_digest(
                material_id=content_digest({"deployment": compiler_id})[:32],
                kind="deployment_policy",
                uri=f"ovk-material:deployment/{compiler_id}",
                payload=lane_input,
                source_revision=head_sha,
            )
        ]
        abstraction = {
            "kind": "deployment_approval_state_machine",
            "input": lane_input,
            "deployment_ir": ir.model_dump(mode="json"),
            "source_compiler": compiler_id,
        }
        provisional = VerificationObligation(
            obligation_id="pending",
            subject=VerificationSubject(repo=repo, head_sha=head_sha, base_sha=base_sha),
            intent_id="no-skipped-approval-state",
            intent_version="0.1.0",
            lane="deployment",
            property_kind="safety",
            severity=RiskSeverity.HIGH,
            compiler_id=compiler_id,
            compiler_version=COMPILER_VERSION,
            materials=materials,
            abstraction=abstraction,
            abstraction_digest=compute_abstraction_digest(abstraction),
            coverage=coverage,
            acceptable_guarantees=["approval_state_reachability_check"],
            required_capabilities=["deployment"],
            policy_digest=policy_digest or content_digest({"lane": "deployment", "policy": policy or {}}),
        )
        return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})

    # Fallback when no recognizable deployment materials exist.
    coverage = AbstractionCoverage(
        status="unknown",
        confidence=0.0,
        extracted_elements=0,
        expected_elements=None,
        warnings=["state machine abstraction missing"],
    )
    materials = [
        MaterialReference(
            material_id="deployment-input",
            kind="diff",
            uri="ovk-material:deployment/input",
            sha256=content_digest(data),
            size_bytes=len(content_digest(data)),
            source_revision=head_sha,
            trusted=False,
        )
    ]
    abstraction = {
        "kind": "deployment_approval_state_machine",
        "input": data,
        "source_compiler": None,
    }
    provisional = VerificationObligation(
        obligation_id="pending",
        subject=VerificationSubject(repo=repo, head_sha=head_sha, base_sha=base_sha),
        intent_id="no-skipped-approval-state",
        intent_version="0.1.0",
        lane="deployment",
        property_kind="safety",
        severity=RiskSeverity.HIGH,
        compiler_id=COMPILER_ID,
        compiler_version=COMPILER_VERSION,
        materials=materials,
        abstraction=abstraction,
        abstraction_digest=compute_abstraction_digest(abstraction),
        coverage=coverage,
        acceptable_guarantees=["approval_state_reachability_check"],
        required_capabilities=["deployment"],
        policy_digest=policy_digest or content_digest({"lane": "deployment", "policy": policy or {}}),
    )
    return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})
