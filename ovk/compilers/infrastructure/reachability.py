"""Reachability and strict-eligibility rules for infrastructure IR."""

from __future__ import annotations

from ovk.compilers.infrastructure.ir import Eligibility, ExposurePath, InfraResourceIR, InfrastructureIR
from ovk.compilers.infrastructure.sensitivity import is_sensitive


def evaluate_eligibility(ir: InfrastructureIR) -> InfrastructureIR:
    """Strict eligibility requires concrete public paths and no unsupported constructs.

    Otherwise the IR is marked ``review``.
    """
    reasons: list[str] = []
    if ir.unsupported_constructs:
        reasons.append("unsupported constructs present")
    if any(resource.support != "supported" for resource in ir.resources):
        reasons.append("one or more resources are partial/unsupported")
    for edge in ir.edges:
        if edge.kind == "declared_public_without_path":
            reasons.append(f"{edge.target} marked public without concrete path")
    # Declared public without concrete path cannot be strict.
    for resource in ir.resources:
        if resource.public_exposure and not any(
            path.is_concrete and path.nodes[-1] == resource.resource_id for path in ir.public_paths
        ):
            reasons.append(f"{resource.resource_id} marked public without concrete path")
    # Sensitive + public without concrete path is always review.
    for resource in ir.resources:
        if (
            is_sensitive(resource.sensitivity)
            and resource.public_exposure
            and not _has_concrete(resource, ir.public_paths)
        ):
            reasons.append(f"sensitive resource {resource.resource_id} lacks concrete exposure path")

    eligibility: Eligibility = "strict" if not reasons and ir.resources else "review"
    if not ir.resources:
        reasons.append("no resources extracted")
        eligibility = "review"
    return ir.model_copy(update={"eligibility": eligibility, "eligibility_reasons": sorted(set(reasons))})


def _has_concrete(resource: InfraResourceIR, paths: list[ExposurePath]) -> bool:
    return any(path.is_concrete and path.nodes[-1] == resource.resource_id for path in paths)


def sensitive_public_violations(ir: InfrastructureIR) -> list[InfraResourceIR]:
    """Return sensitive resources that are publicly reachable via concrete paths."""
    return [
        resource
        for resource in ir.resources
        if is_sensitive(resource.sensitivity) and resource.public_exposure and _has_concrete(resource, ir.public_paths)
    ]
