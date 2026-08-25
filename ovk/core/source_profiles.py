"""Source-profile identifiers and candidate-evidence gates.

A source profile identifies a bounded compiler/support-contract pair. Local
fixture coverage is useful evidence that a profile is a maturity candidate, but
it is never sufficient by itself to promote a profile to strict eligibility.
Normative strict promotion is owned by ``source_profile_maturity`` and requires
the complete machine qualification contract.
"""

from __future__ import annotations

from typing import Any, Literal

SourceProfileId = Literal[
    "authorization.fastapi.ast_v1",
    "authorization.express.ast_v1",
    "infrastructure.terraform.plan_recursive_v1",
    "infrastructure.kubernetes.controller_reachability_v1",
    "ci_secrets.actions.permissions_flow_v1",
    "deployment.trusted_profile_v1",
]

KNOWN_SOURCE_PROFILES: frozenset[str] = frozenset(
    {
        "authorization.fastapi.ast_v1",
        "authorization.express.ast_v1",
        "infrastructure.terraform.plan_recursive_v1",
        "infrastructure.kubernetes.controller_reachability_v1",
        "ci_secrets.actions.permissions_flow_v1",
        "deployment.trusted_profile_v1",
    }
)

PROFILE_COMPILER_BINDINGS: dict[str, str] = {
    "authorization.fastapi.ast_v1": "ovk.compilers.authorization.fastapi_ast:FastApiAstAuthorizationCompiler",
    "authorization.express.ast_v1": "ovk.compilers.authorization.express_ast:ExpressAstAuthorizationCompiler",
    "infrastructure.terraform.plan_recursive_v1": "ovk.compilers.infrastructure.terraform_plan:compile_terraform_plan",
    "infrastructure.kubernetes.controller_reachability_v1": "ovk.compilers.infrastructure.kubernetes:compile_kubernetes_objects",
    "ci_secrets.actions.permissions_flow_v1": "ovk.compilers.github_actions.trust_flow:compile_workflow_trust",
    "deployment.trusted_profile_v1": "ovk.compilers.deployment.deployment_state:compile_deployment_state",
}

LANE_DEFAULT_PROFILES: dict[str, tuple[str, ...]] = {
    "authorization": (
        "authorization.fastapi.ast_v1",
        "authorization.express.ast_v1",
    ),
    "infrastructure": (
        "infrastructure.terraform.plan_recursive_v1",
        "infrastructure.kubernetes.controller_reachability_v1",
    ),
    "ci_secrets": ("ci_secrets.actions.permissions_flow_v1",),
    "deployment": ("deployment.trusted_profile_v1",),
}


def is_known_source_profile(profile_id: str | None) -> bool:
    return bool(profile_id) and profile_id in KNOWN_SOURCE_PROFILES


def source_profile_candidate_evidence_complete(
    *,
    profile_id: str | None,
    materials_trusted: bool,
    coverage_complete: bool,
    enforcement_test_present: bool,
) -> bool:
    """Return whether the legacy local proof is complete enough for candidacy.

    This predicate MUST NOT be used to grant ``source_profile_strict_eligible``.
    Strict promotion is defined only by ``SourceProfileQualification.strict_ready``.
    """
    return (
        is_known_source_profile(profile_id)
        and materials_trusted
        and coverage_complete
        and enforcement_test_present
    )


def profiles_from_policy(policy: dict[str, Any] | None, *, lane: str) -> list[str]:
    """Extract requested source profiles for a lane from repository policy."""
    if not isinstance(policy, dict):
        return []
    section = policy.get("source_profiles")
    if not isinstance(section, dict):
        return []
    raw = section.get(lane, section.get("profiles", []))
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if is_known_source_profile(str(item))]


def compiler_binding_for(profile_id: str) -> str | None:
    """Return the compiler binding string for a known profile, if any."""
    if not is_known_source_profile(profile_id):
        return None
    return PROFILE_COMPILER_BINDINGS.get(profile_id)
