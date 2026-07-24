"""Backend-neutral self-protection obligation compiler."""

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

COMPILER_ID = "ovk.self_protection.neutral.v1"
COMPILER_VERSION = "0.1.0"

TRUSTED_METADATA_PROVENANCE_KINDS: frozenset[str] = frozenset(
    {
        "protected_base_workflow",
        "signed_service",
        "maintainer_supplied",
    }
)


def resolve_metadata_trusted(policy: dict[str, Any] | None) -> bool:
    """Return True only when policy supplies explicit trusted provenance."""
    if not isinstance(policy, dict):
        return False
    trust = policy.get("trust")
    if not isinstance(trust, dict):
        return False
    if not bool(trust.get("metadata_trusted")):
        return False
    provenance = trust.get("provenance_kind") or trust.get("provenance")
    if provenance not in TRUSTED_METADATA_PROVENANCE_KINDS:
        return False
    return True


def _phase(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    return value if isinstance(value, dict) else {}


def compile_self_protection_obligation(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
    policy_digest: str | None = None,
    metadata_trusted: bool = False,
) -> VerificationObligation:
    """Compile a self-protection obligation with base/head metadata materials.

    When ``metadata_trusted`` is True, before/after required-check materials are
    marked trusted. Untrusted metadata cannot authorize allow under enforcement.
    Trust requires explicit policy provenance via ``resolve_metadata_trusted``.
    """
    before = _phase(data, "before")
    after = _phase(data, "after")
    has_before = isinstance(before.get("required_checks"), list)
    has_after = isinstance(after.get("required_checks"), list)
    warnings: list[str] = []
    if not has_before:
        warnings.append("before.required_checks metadata missing")
    if not has_after:
        warnings.append("after.required_checks metadata missing")
    if has_before and has_after:
        coverage = AbstractionCoverage(
            status="complete",
            confidence=1.0 if metadata_trusted else 0.6,
            extracted_elements=2,
            expected_elements=2,
            warnings=warnings,
        )
    elif has_before or has_after:
        coverage = AbstractionCoverage(
            status="partial",
            confidence=0.4,
            extracted_elements=1,
            expected_elements=2,
            warnings=warnings,
        )
    else:
        coverage = AbstractionCoverage(
            status="unknown",
            confidence=0.0,
            extracted_elements=0,
            expected_elements=2,
            warnings=warnings or ["base and head required-check metadata missing"],
        )

    materials = [
        material_reference_from_payload(
            material_id="self-protection-before",
            kind="branch_protection",
            uri="ovk-material:self_protection/before",
            payload=before,
            source_revision=base_sha,
            trusted=metadata_trusted and has_before,
        ),
        material_reference_from_payload(
            material_id="self-protection-after",
            kind="branch_protection",
            uri="ovk-material:self_protection/after",
            payload=after,
            source_revision=head_sha,
            trusted=metadata_trusted and has_after,
        ),
        material_reference_from_payload(
            material_id="self-protection-input",
            kind="diff",
            uri="ovk-material:self_protection/input",
            payload=data,
            source_revision=head_sha,
            trusted=False,
        ),
    ]
    abstraction = {
        "kind": "self_protection_gate_preservation",
        "input": data,
        "metadata_trusted": metadata_trusted,
        "base_sha": base_sha,
        "head_sha": head_sha,
    }
    provisional = VerificationObligation(
        obligation_id="pending",
        subject=VerificationSubject(repo=repo, head_sha=head_sha, base_sha=base_sha),
        intent_id="agent-cannot-disable-own-ci-gate",
        intent_version="0.1.0",
        lane="self_protection",
        property_kind="invariant",
        severity=RiskSeverity.CRITICAL,
        compiler_id=COMPILER_ID,
        compiler_version=COMPILER_VERSION,
        materials=materials,
        abstraction=abstraction,
        abstraction_digest=compute_abstraction_digest(abstraction),
        coverage=coverage,
        acceptable_guarantees=["policy_evaluation"],
        required_capabilities=["self_protection"],
        policy_digest=policy_digest or content_digest({"lane": "self_protection"}),
    )
    return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})
