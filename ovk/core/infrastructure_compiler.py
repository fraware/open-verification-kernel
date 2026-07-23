"""Backend-neutral infrastructure obligation compiler."""

from __future__ import annotations

from typing import Any

from ovk.adapters.infra.validation import validate_infra_input
from ovk.core.bundle import content_digest
from ovk.core.compiler_bridge import (
    compile_infrastructure_ir,
    infrastructure_coverage,
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

COMPILER_ID = "ovk.infrastructure.neutral.v1"
COMPILER_VERSION = "0.2.0"


def compile_infrastructure_obligation(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
    policy_digest: str | None = None,
    policy: dict[str, Any] | None = None,
) -> VerificationObligation:
    """Compile a backend-neutral infrastructure exposure obligation.

    When a terraform plan or kubernetes objects are present, the corresponding
    source compiler builds the IR. Legacy resource graphs remain supported.
    """
    source = compile_infrastructure_ir(data)
    if source is not None:
        ir, compiler_id = source
        lane_input = ir.to_lane_input()
        for key in ("author_type", "agent", "task"):
            if key in data:
                lane_input[key] = data[key]
        coverage = infrastructure_coverage(ir)
        kind = "terraform_plan" if "terraform" in compiler_id else "kubernetes_object"
        materials = [
            material_refs_from_digest(
                material_id=content_digest({"infra": compiler_id})[:32],
                kind=kind,
                uri=f"ovk-material:infrastructure/{compiler_id}",
                payload=lane_input,
                source_revision=head_sha,
            )
        ]
        abstraction = {
            "kind": "infrastructure_exposure_graph",
            "input": lane_input,
            "infrastructure_ir": ir.model_dump(mode="json"),
            "source_compiler": compiler_id,
            "eligibility": ir.eligibility,
        }
        provisional = VerificationObligation(
            obligation_id="pending",
            subject=VerificationSubject(repo=repo, head_sha=head_sha, base_sha=base_sha),
            intent_id="no-public-sensitive-resource",
            intent_version="0.1.0",
            lane="infrastructure",
            property_kind="forbidden_configuration",
            severity=RiskSeverity.HIGH,
            compiler_id=compiler_id,
            compiler_version=COMPILER_VERSION,
            materials=materials,
            abstraction=abstraction,
            abstraction_digest=compute_abstraction_digest(abstraction),
            coverage=coverage,
            acceptable_guarantees=["exposure_graph_check"],
            required_capabilities=["infrastructure"],
            policy_digest=policy_digest
            or content_digest({"lane": "infrastructure", "policy": policy or {}}),
        )
        return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})

    issues = validate_infra_input(data)
    resources = data.get("resources") if isinstance(data.get("resources"), list) else []
    extracted = len(resources)
    issue_messages = [f"{issue.path}: {issue.message}" for issue in issues]
    if issues and extracted == 0:
        coverage = AbstractionCoverage(
            status="unknown",
            confidence=0.0,
            extracted_elements=0,
            expected_elements=None,
            unsupported_constructs=issue_messages,
            warnings=["infrastructure abstraction missing or malformed"],
        )
    elif issues:
        coverage = AbstractionCoverage(
            status="partial",
            confidence=0.4,
            extracted_elements=extracted,
            expected_elements=extracted,
            unsupported_constructs=issue_messages,
            warnings=["infrastructure input failed validation checks"],
        )
    else:
        coverage = AbstractionCoverage(
            status="complete" if extracted else "unknown",
            confidence=1.0 if extracted else 0.0,
            extracted_elements=extracted,
            expected_elements=extracted,
        )

    materials = [
        MaterialReference(
            material_id="infrastructure-input",
            kind="diff",
            uri="ovk-material:infrastructure/input",
            sha256=content_digest(data),
            size_bytes=len(content_digest(data)),
            source_revision=head_sha,
            trusted=False,
        )
    ]
    abstraction = {
        "kind": "infrastructure_exposure_graph",
        "input": data,
        "validation_issues": [issue.to_dict() for issue in issues],
        "source_compiler": None,
    }
    provisional = VerificationObligation(
        obligation_id="pending",
        subject=VerificationSubject(repo=repo, head_sha=head_sha, base_sha=base_sha),
        intent_id="no-public-sensitive-resource",
        intent_version="0.1.0",
        lane="infrastructure",
        property_kind="forbidden_configuration",
        severity=RiskSeverity.HIGH,
        compiler_id=COMPILER_ID,
        compiler_version=COMPILER_VERSION,
        materials=materials,
        abstraction=abstraction,
        abstraction_digest=compute_abstraction_digest(abstraction),
        coverage=coverage,
        acceptable_guarantees=["exposure_graph_check"],
        required_capabilities=["infrastructure"],
        policy_digest=policy_digest or content_digest({"lane": "infrastructure", "policy": policy or {}}),
    )
    return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})
