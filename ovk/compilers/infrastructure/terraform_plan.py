"""Strict Terraform plan compiler consuming ``terraform show -json`` shape.

Regex is never authoritative. Only known plan JSON fields are consumed; unknown
shapes are marked unsupported and force review eligibility.
"""

from __future__ import annotations

from typing import Any

from ovk.compilers.infrastructure.exposure_graph import (
    apply_concrete_exposure,
    build_edges,
    concrete_public_paths,
)
from ovk.compilers.infrastructure.ir import InfraResourceIR, InfrastructureIR
from ovk.compilers.infrastructure.reachability import evaluate_eligibility
from ovk.compilers.infrastructure.sensitivity import sensitivity_from_tags


def compile_terraform_plan(plan: dict[str, Any]) -> InfrastructureIR:
    """Compile a terraform show -json document into infrastructure IR."""
    warnings: list[str] = []
    unsupported: list[str] = []
    resources: list[InfraResourceIR] = []

    if not isinstance(plan, dict):
        return evaluate_eligibility(
            InfrastructureIR(
                source_kind="terraform_plan",
                unsupported_constructs=["plan_not_object"],
                warnings=["terraform plan root must be an object"],
            )
        )

    format_version = plan.get("format_version")
    if format_version is None:
        unsupported.append("missing_format_version")
    resource_changes = plan.get("resource_changes")
    if resource_changes is None:
        # Planned values fallback is accepted as partial.
        planned = plan.get("planned_values", {})
        root = planned.get("root_module", {}) if isinstance(planned, dict) else {}
        resource_changes = []
        for item in root.get("resources", []) if isinstance(root, dict) else []:
            if isinstance(item, dict):
                resource_changes.append(
                    {
                        "address": item.get("address") or item.get("name"),
                        "type": item.get("type"),
                        "change": {"after": item.get("values", {})},
                    }
                )
        warnings.append("resource_changes missing; used planned_values.root_module.resources")

    if not isinstance(resource_changes, list):
        unsupported.append("resource_changes_not_list")
        resource_changes = []

    for index, change in enumerate(resource_changes):
        if not isinstance(change, dict):
            unsupported.append(f"resource_changes[{index}]_not_object")
            continue
        address = str(change.get("address") or f"resource[{index}]")
        rtype = str(change.get("type") or "unknown")
        change_body = change.get("change", {})
        after = change_body.get("after") if isinstance(change_body, dict) else None
        if after is None:
            unsupported.append(f"{address}:missing_after")
            continue
        if not isinstance(after, dict):
            unsupported.append(f"{address}:after_not_object")
            continue
        tags = after.get("tags") if isinstance(after.get("tags"), dict) else {}
        sensitivity = sensitivity_from_tags(tags, after)
        paths: list[str] = []
        if isinstance(after.get("exposure_paths"), list):
            paths = [str(item) for item in after["exposure_paths"]]
        elif after.get("acl") in {"public-read", "public-read-write", "website"}:
            paths = [f"acl:{after.get('acl')}"]
        elif after.get("internet_accessible") is True:
            paths = ["internet_accessible"]
        public = bool(paths) or after.get("public_exposure") is True
        resources.append(
            InfraResourceIR(
                resource_id=address,
                resource_type=rtype,
                kind="terraform",
                sensitivity=sensitivity,
                public_exposure=public,
                exposure_paths=paths,
                attributes={"format_version": format_version},
            )
        )

    edges = build_edges(resources)
    paths = concrete_public_paths(resources, edges)
    resources = apply_concrete_exposure(resources, paths)
    ir = InfrastructureIR(
        source_kind="terraform_plan",
        resources=resources,
        edges=edges,
        public_paths=paths,
        unsupported_constructs=sorted(set(unsupported)),
        warnings=warnings,
    )
    return evaluate_eligibility(ir)
