"""Source-profile identifiers and eligibility gates (Sprint 6).

Profiles authorize deeper compilers when trusted materials are present.
They do not by themselves grant ``externally_calibrated_strict`` status.
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

# Maps profile IDs to the production compiler entrypoints that implement them.
PROFILE_COMPILER_BINDINGS: dict[str, str] = {
    "authorization.fastapi.ast_v1": "ovk.compilers.authorization.fastapi_ast:FastApiAstAuthorizationCompiler",
    "authorization.express.ast_v1": "ovk.compilers.authorization.express:ExpressAuthorizationCompiler",
    "infrastructure.terraform.plan_recursive_v1": "ovk.compilers.infrastructure.terraform_plan:compile_terraform_plan",
    "infrastructure.kubernetes.controller_reachability_v1": "ovk.compilers.infrastructure.kubernetes:compile_kubernetes_objects",
    "ci_secrets.actions.permissions_flow_v1": "ovk.compilers.github_actions.trust_flow:compile_workflow_trust",
    "deployment.trusted_profile_v1": "ovk.compilers.deployment.explicit_schema:compile_explicit_schema",
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

# Remaining gaps (honest): Express module-graph depth, Actions composite recursion
# beyond current trust_flow expansion, and deployment strictness without an
# explicit trusted_profile material.


def is_known_source_profile(profile_id: str | None) -> bool:
    return bool(profile_id) and profile_id in KNOWN_SOURCE_PROFILES


def source_profile_strict_eligible(
    *,
    profile_id: str | None,
    materials_trusted: bool,
    coverage_complete: bool,
    enforcement_test_present: bool,
) -> bool:
    """Return True when a template may claim source_profile_strict_eligible."""
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
