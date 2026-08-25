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


def re_search_index(address: str) -> bool:
    return "[" in address and "]" in address


def _provider_family_paths(rtype: str, after: dict[str, Any]) -> list[str]:
    """Bounded AWS/Azure/GCP family paths — never a bare public=true."""
    paths: list[str] = []
    if after.get("acl") in {"public-read", "public-read-write", "website"}:
        paths.append(f"acl:{after.get('acl')}")
    if after.get("internet_accessible") is True:
        paths.append("internet_accessible")
    cidrs = after.get("cidr_blocks")
    if isinstance(cidrs, list) and any(str(item) in {"0.0.0.0/0", "::/0"} for item in cidrs):
        if rtype.startswith("aws_"):
            paths.append("aws:cidr:internet->sg")
        elif rtype.startswith("azurerm_"):
            paths.append("azure:cidr:internet->nsg")
        elif rtype.startswith("google_"):
            paths.append("gcp:cidr:internet->firewall")
        else:
            paths.append("cidr:internet")
    ingress = after.get("ingress")
    if isinstance(ingress, list):
        for rule in ingress:
            if not isinstance(rule, dict):
                continue
            rule_cidrs = rule.get("cidr_blocks") or rule.get("ipv6_cidr_blocks") or []
            if isinstance(rule_cidrs, list) and any(str(item) in {"0.0.0.0/0", "::/0"} for item in rule_cidrs):
                paths.append(f"{rtype}:ingress:internet")
                break
    return paths


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
        if not isinstance(change_body, dict):
            change_body = {}
        after = change_body.get("after")
        after_unknown = change_body.get("after_unknown")
        after_sensitive = change_body.get("after_sensitive")
        actions = change_body.get("actions") if isinstance(change_body.get("actions"), list) else []

        # Moved / count / for_each markers force careful eligibility.
        if change.get("action_reason") == "move" or "moved" in {str(a) for a in actions}:
            warnings.append(f"{address}:moved_resource")
        if re_search_index(address):
            warnings.append(f"{address}:count_or_for_each_index")

        unknown_exposure = False
        if isinstance(after_unknown, dict):
            for key in ("cidr_blocks", "ingress", "egress", "public_exposure", "acl", "internet_accessible", "security_groups"):
                if after_unknown.get(key):
                    unknown_exposure = True
                    unsupported.append(f"{address}:after_unknown:{key}")
        if isinstance(after_sensitive, dict) and any(after_sensitive.get(k) for k in ("cidr_blocks", "ingress", "acl")):
            warnings.append(f"{address}:sensitive_exposure_fields")
            # Sensitive unknown exposure must not be treated as private.
            unknown_exposure = True

        if after is None and unknown_exposure:
            # Unknown exposure → review, never public=false claim.
            resources.append(
                InfraResourceIR(
                    resource_id=address,
                    resource_type=rtype,
                    kind="terraform",
                    sensitivity="unknown",
                    public_exposure=False,
                    exposure_paths=[],
                    attributes={
                        "format_version": format_version,
                        "exposure_status": "unknown_requires_review",
                        "after_unknown": after_unknown,
                    },
                )
            )
            continue
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
        else:
            paths = _provider_family_paths(rtype, after)
        if unknown_exposure:
            # Do not mint public=false from unknown; force review via unsupported.
            paths = []
        public = bool(paths) or after.get("public_exposure") is True
        if after.get("public_exposure") is True and not paths:
            # Generic public=true without concrete path cannot be strict.
            unsupported.append(f"{address}:generic_public_true_without_path")
            # Keep declared public so eligibility records "without concrete path".
            public = True
            paths = []
        attributes: dict[str, Any] = {"format_version": format_version}
        if change.get("module_address"):
            attributes["module_address"] = change["module_address"]
        if used_recursive_profile:
            attributes["source_profile"] = _SOURCE_PROFILE_ID
        if unknown_exposure:
            attributes["exposure_status"] = "unknown_requires_review"
        # Bind TF/provider metadata when present.
        if isinstance(plan.get("terraform_version"), str):
            attributes["terraform_version"] = plan["terraform_version"]
        provider = change.get("provider_name")
        if provider:
            attributes["provider_name"] = provider
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
