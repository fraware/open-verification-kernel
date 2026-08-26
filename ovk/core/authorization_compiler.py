"""Backend-neutral authorization obligation compiler."""

from __future__ import annotations

from typing import Any

from ovk.adapters.z3.obligation import build_authorization_obligation, obligation_to_dict
from ovk.adapters.z3.validation import validate_authorization_input
from ovk.compilers.authorization import CoveragePolicy, strict_allow_permitted
from ovk.core.bundle import content_digest
from ovk.core.compiler_bridge import compile_authorization_ir, coverage_policy_from_dict
from ovk.core.execution_models import (
    AbstractionCoverage,
    VerificationObligation,
    compute_abstraction_digest,
    compute_obligation_id,
)
from ovk.core.materials import material_reference_from_payload
from ovk.core.models import RiskSeverity, VerificationSubject
from ovk.core.source_profiles import is_known_source_profile

COMPILER_ID = "ovk.authorization.neutral.v1"
COMPILER_VERSION = "0.2.0"


def _source_profile_request_issue(data: dict[str, Any]) -> str | None:
    """Validate an explicit authorization source-profile request.

    Profile identity is trust-critical metadata: an unknown or framework-
    incompatible profile must not fall through to a different compiler while
    retaining the requested profile name in evidence.
    """
    requested = str(data.get("source_profile_id") or data.get("source_profile") or "").strip()
    framework = str(data.get("framework") or "").strip().lower()

    if framework and framework not in {"fastapi", "express"}:
        return f"unsupported_authorization_framework:{framework}"

    if not requested:
        return None
    if not is_known_source_profile(requested) or not requested.startswith("authorization."):
        return f"unknown_source_profile:{requested}"

    expected_prefix = f"authorization.{framework}." if framework else None
    if expected_prefix and not requested.startswith(expected_prefix):
        return f"source_profile_framework_mismatch:{requested}:framework={framework}"
    return None


def compile_authorization_obligation(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
    policy_digest: str | None = None,
    policy: dict[str, Any] | None = None,
) -> VerificationObligation:
    """Compile a backend-neutral authorization obligation from lane input.

    When base+head source materials are present, FastAPI/Express compilers
    produce the IR and documented ``AbstractionCoverage``. Legacy route
    abstractions remain supported without claiming source-grounded coverage.

    Coverage is ``complete`` when validation finds no structural issues and at
    least one route is present; ``partial`` when routes exist with warnings;
    ``unknown`` when the abstraction is missing or malformed.

    Explicit source-profile identity is validated before source compilation.
    Unknown or framework-incompatible profile requests fail closed into the
    neutral path and cannot mint a profile-qualified compiler identity.

    Strict allow is blocked unless coverage is complete, or policy explicitly
    accepts partial coverage (``coverage.accept_partial_coverage``).
    """
    coverage_policy = coverage_policy_from_dict(policy)
    profile_issue = _source_profile_request_issue(data)
    source = None
    if profile_issue is None:
        source = compile_authorization_ir(
            data,
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            coverage_policy=coverage_policy,
        )

    if source is not None:
        ir, coverage, compiler_id, materials = source
        lane_input = ir.to_lane_input()
        for key in ("author_type", "agent", "task"):
            if key in data:
                lane_input[key] = data[key]
        auth_obligation = build_authorization_obligation(lane_input)
        abstraction = {
            "kind": "authorization_route_reachability",
            "input": lane_input,
            "obligation": obligation_to_dict(auth_obligation),
            "authorization_ir": ir.model_dump(mode="json"),
            "source_compiler": compiler_id,
            "strict_allow_permitted": strict_allow_permitted(coverage, coverage_policy),
            "coverage_policy": {
                "accept_partial_coverage": coverage_policy.accept_partial_coverage,
            },
        }
        material_refs = [
            material_reference_from_payload(
                material_id=content_digest({"path": path})[:32],
                kind="source_file",
                uri=f"ovk-material:authorization/source/{path}",
                payload={"path": path, "base": materials.base_text(path), "head": materials.head_text(path)},
                source_revision=head_sha,
            )
            for path in materials.paths
        ]
        if not material_refs:
            material_refs = [
                material_reference_from_payload(
                    material_id=content_digest({"authorization": lane_input})[:32],
                    kind="diff",
                    uri="ovk-material:authorization/input",
                    payload=lane_input,
                    source_revision=head_sha,
                    trusted=False,
                )
            ]
        provisional = VerificationObligation(
            obligation_id="pending",
            subject=VerificationSubject(repo=repo, head_sha=head_sha, base_sha=base_sha),
            intent_id="no-admin-route-bypass",
            intent_version="0.1.0",
            lane="authorization",
            property_kind="access_control",
            severity=RiskSeverity.HIGH,
            compiler_id=compiler_id,
            compiler_version=COMPILER_VERSION,
            materials=material_refs,
            abstraction=abstraction,
            abstraction_digest=compute_abstraction_digest(abstraction),
            coverage=coverage,
            acceptable_guarantees=["smt_refutation_search", "deterministic_witness"],
            required_capabilities=["authorization"],
            policy_digest=policy_digest or content_digest({"lane": "authorization", "policy": policy or {}}),
        )
        return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})

    issues = list(validate_authorization_input(data))
    if profile_issue is not None:
        issues.insert(0, profile_issue)
    auth_obligation = build_authorization_obligation(data)
    abstraction = {
        "kind": "authorization_route_reachability",
        "input": data,
        "obligation": obligation_to_dict(auth_obligation),
        "validation_issues": issues,
        "source_compiler": None,
        "strict_allow_permitted": False,
        "coverage_policy": {
            "accept_partial_coverage": coverage_policy.accept_partial_coverage,
        },
    }
    extracted = len(auth_obligation.routes)
    if issues and extracted == 0:
        coverage = AbstractionCoverage(
            status="unknown",
            confidence=0.0,
            extracted_elements=0,
            expected_elements=None,
            unsupported_constructs=[str(issue) for issue in issues],
            warnings=["authorization abstraction missing or malformed"],
        )
    elif issues:
        coverage = AbstractionCoverage(
            status="partial",
            confidence=0.4,
            extracted_elements=extracted,
            expected_elements=extracted,
            unsupported_constructs=[str(issue) for issue in issues],
            warnings=["authorization input failed validation checks"],
        )
    else:
        coverage = AbstractionCoverage(
            status="complete" if extracted else "unknown",
            confidence=1.0 if extracted else 0.0,
            extracted_elements=extracted,
            expected_elements=extracted,
        )
    abstraction["strict_allow_permitted"] = strict_allow_permitted(coverage, coverage_policy)

    materials = [
        material_reference_from_payload(
            material_id=content_digest({"authorization": data})[:32],
            kind="diff",
            uri="ovk-material:authorization/input",
            payload=data,
            source_revision=head_sha,
            trusted=False,
        )
    ]
    provisional = VerificationObligation(
        obligation_id="pending",
        subject=VerificationSubject(repo=repo, head_sha=head_sha, base_sha=base_sha),
        intent_id="no-admin-route-bypass",
        intent_version="0.1.0",
        lane="authorization",
        property_kind="access_control",
        severity=RiskSeverity.HIGH,
        compiler_id=COMPILER_ID,
        compiler_version=COMPILER_VERSION,
        materials=materials,
        abstraction=abstraction,
        abstraction_digest=compute_abstraction_digest(abstraction),
        coverage=coverage,
        acceptable_guarantees=["smt_refutation_search", "deterministic_witness"],
        required_capabilities=["authorization"],
        policy_digest=policy_digest or content_digest({"lane": "authorization", "policy": policy or {}}),
    )
    return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})


def authorization_strict_allow_ok(
    obligation: VerificationObligation,
    *,
    policy: CoveragePolicy | None = None,
) -> bool:
    """Whether an allow recommendation is permitted under coverage policy."""
    policy = policy or CoveragePolicy()
    flagged = obligation.abstraction.get("strict_allow_permitted")
    if isinstance(flagged, bool):
        return flagged
    return strict_allow_permitted(obligation.coverage, policy)
