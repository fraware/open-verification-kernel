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
from ovk.core.metadata_provenance import (
    acquisition_is_trusted,
    allowed_provenance_kinds_from_policy,
    parse_acquisition_record,
)
from ovk.core.models import RiskSeverity, VerificationSubject

COMPILER_ID = "ovk.self_protection.neutral.v1"
COMPILER_VERSION = "0.2.0"


def resolve_metadata_trusted(
    policy: dict[str, Any] | None,
    *,
    data: dict[str, Any] | None = None,
    repo: str | None = None,
    head_sha: str | None = None,
    base_sha: str | None = None,
) -> bool:
    """Return trust only for a digest-bound acquisition record.

    Historical ``trust.metadata_trusted`` and ``trust.provenance_kind`` fields no
    longer authorize trust by themselves. Policy may restrict which provenance
    kinds are accepted, but the assertion must come from the acquired material.
    """
    if not isinstance(data, dict) or not repo or not head_sha:
        return False
    trusted, _reasons, _record = acquisition_is_trusted(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        allowed_provenance_kinds=allowed_provenance_kinds_from_policy(policy),
    )
    return trusted


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
    """Compile gate-preservation semantics over bound before/after metadata."""
    before = _phase(data, "before")
    after = _phase(data, "after")
    has_before = isinstance(before.get("required_checks"), list)
    has_after = isinstance(after.get("required_checks"), list)
    warnings: list[str] = []
    if not has_before:
        warnings.append("before.required_checks metadata missing")
    if not has_after:
        warnings.append("after.required_checks metadata missing")
    if not metadata_trusted:
        warnings.append("branch-protection metadata lacks trusted digest-bound acquisition provenance")

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
        # The complete input binds the acquisition record itself into the
        # material set, preventing provenance substitution after collection.
        material_reference_from_payload(
            material_id="self-protection-input",
            kind="diff",
            uri="ovk-material:self_protection/input",
            payload=data,
            source_revision=head_sha,
            trusted=False,
        ),
    ]
    acquisition = parse_acquisition_record(data)
    abstraction = {
        "kind": "self_protection_gate_preservation",
        "input": data,
        "metadata_trusted": metadata_trusted,
        "metadata_acquisition": acquisition.model_dump(mode="json") if acquisition else None,
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
