"""Helpers to build typed obligations from legacy lane inputs (shadow path)."""

from __future__ import annotations

from typing import Any

from ovk.core.bundle import content_digest
from ovk.core.execution_models import (
    AbstractionCoverage,
    VerificationObligation,
    compute_abstraction_digest,
    compute_obligation_id,
)
from ovk.core.materials import material_reference_from_payload
from ovk.core.models import RiskSeverity, VerificationSubject

LANE_PROPERTY_KIND: dict[str, str] = {
    "self_protection": "invariant",
    "authorization": "access_control",
    "infrastructure": "forbidden_configuration",
    "ci_secrets": "data_boundary",
    "deployment": "safety",
}

LANE_ACCEPTABLE_GUARANTEES: dict[str, list[str]] = {
    "self_protection": ["policy_evaluation"],
    "authorization": ["smt_refutation_search", "deterministic_witness"],
    "infrastructure": ["policy_evaluation"],
    "ci_secrets": ["workflow_secrets_boundary_check"],
    "deployment": ["state_machine_safety"],
}


def build_shadow_obligation(
    *,
    lane: str,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    intent_id: str,
    policy_digest: str | None = None,
) -> VerificationObligation:
    """Construct a backend-neutral obligation for shadow control-plane execution."""
    subject = VerificationSubject(repo=repo, head_sha=head_sha, base_sha=base_sha)
    material = material_reference_from_payload(
        material_id=content_digest({"lane": lane, "input": data})[:32],
        kind="diff",
        uri=f"ovk-material:lane/{lane}",
        payload=data,
        source_revision=head_sha,
        trusted=False,
    )
    abstraction = dict(data)
    abs_digest = compute_abstraction_digest(abstraction)
    provisional = VerificationObligation(
        obligation_id="pending",
        subject=subject,
        intent_id=intent_id,
        intent_version="0.1.0",
        lane=lane,
        property_kind=LANE_PROPERTY_KIND.get(lane, "safety"),
        severity=RiskSeverity.HIGH,
        compiler_id="ovk.shadow.legacy_input.v1",
        compiler_version="0.1.0",
        materials=[material],
        abstraction=abstraction,
        abstraction_digest=abs_digest,
        coverage=AbstractionCoverage(
            status="unknown",
            confidence=0.5,
            extracted_elements=1,
            expected_elements=None,
            warnings=["shadow obligation compiled from legacy lane input"],
        ),
        acceptable_guarantees=list(LANE_ACCEPTABLE_GUARANTEES.get(lane, ["policy_evaluation"])),
        required_capabilities=[lane],
        policy_digest=policy_digest or content_digest({"lane": lane}),
    )
    return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})
