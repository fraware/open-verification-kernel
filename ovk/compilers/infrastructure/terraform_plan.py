"""Strict Terraform plan compiler consuming ``terraform show -json`` shape.

Regex is never authoritative. Only known plan JSON fields are consumed; unknown
shapes are marked unsupported and force review eligibility.

Profile ``infrastructure.terraform.plan_recursive_v1`` expands
``planned_values`` / ``prior_state`` child modules recursively instead of
stopping at ``root_module``.
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

_SOURCE_PROFILE_ID = "infrastructure.terraform.plan_recursive_v1"


def _walk_module_resources(
    module: dict[str, Any],
    *,
    module_address: str,
    out: list[dict[str, Any]],
    warnings: list[str],
    depth: int = 0,
    max_depth: int = 32,
) -> None:
    """Recursively collect resources from a Terraform module tree."""
    if depth > max_depth:
        warnings.append(f"module_depth_exceeded:{module_address or 'root'}")
        return
    resources = module.get("resources")
    if isinstance(resources, list):
        for item in resources:
            if not isinstance(item, dict):
                continue
            address = item.get("address")
            if not address:
                name = item.get("name") or "unnamed"
                rtype = item.get("type") or "unknown"
                prefix = f"{module_address}." if module_address else ""
                address = f"{prefix}{rtype}.{name}"
            out.append(
                {
                    "address": address,
                    "type": item.get("type"),
                    "change": {"after": item.get("values", {})},
                    "module_address": module_address or "root",
                }
            )
    children = module.get("child_modules")
    if not isinstance(children, list):
        return
    for child in children:
        if not isinstance(child, dict):
            continue
        child_addr = str(child.get("address") or f"{module_address}.module.unknown")
        _walk_module_resources(
            child,
            module_address=child_addr,
            out=out,
            warnings=warnings,
            depth=depth + 1,
            max_depth=max_depth,
        )


def expand_planned_values_recursively(plan: dict[str, Any], warnings: list[str]) -> list[dict[str, Any]]:
    """Expand ``planned_values`` including nested ``child_modules``."""
    planned = plan.get("planned_values", {})
    if not isinstance(planned, dict):
        return []
    root = planned.get("root_module", {})
    if not isinstance(root, dict):
        return []
    out: list[dict[str, Any]] = []
    _walk_module_resources(root, module_address="", out=out, warnings=warnings)
    return out


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
    used_recursive_profile = False
    if resource_changes is None:
        # Planned values fallback with recursive child_modules expansion.
        resource_changes = expand_planned_values_recursively(plan, warnings)
        used_recursive_profile = True
        warnings.append("resource_changes missing; used planned_values recursive module walk")
        warnings.append(f"compiled_with_source_profile:{_SOURCE_PROFILE_ID}")
    elif isinstance(resource_changes, list):
        # Also surface nested planned_values modules as supplemental when present.
        nested = expand_planned_values_recursively(plan, warnings)
        if nested:
            existing = {
                str(item.get("address")) for item in resource_changes if isinstance(item, dict) and item.get("address")
            }
            added = 0
            for item in nested:
                address = str(item.get("address") or "")
                if address and address not in existing:
                    resource_changes.append(item)
                    existing.add(address)
                    added += 1
            if added:
                used_recursive_profile = True
                warnings.append(f"recursive_modules_added:{added}")
                warnings.append(f"compiled_with_source_profile:{_SOURCE_PROFILE_ID}")

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
        attributes: dict[str, Any] = {"format_version": format_version}
        if change.get("module_address"):
            attributes["module_address"] = change["module_address"]
        if used_recursive_profile:
            attributes["source_profile"] = _SOURCE_PROFILE_ID
        resources.append(
            InfraResourceIR(
                resource_id=address,
                resource_type=rtype,
                kind="terraform",
                sensitivity=sensitivity,
                public_exposure=public,
                exposure_paths=paths,
                attributes=attributes,
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
