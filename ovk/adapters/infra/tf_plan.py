"""Terraform-plan-style normalization for infrastructure exposure checks.

This module intentionally supports a small, explicit subset of Terraform plan
JSON shapes. Unsupported shapes should be handled upstream or treated as
insufficient evidence.
"""

from __future__ import annotations

from typing import Any


SENSITIVITY_KEYS = ("sensitivity", "data_sensitivity", "classification", "data_classification")
PUBLIC_ACL_VALUES = {"public-read", "public-read-write", "website"}


def _tags(after: dict[str, Any]) -> dict[str, Any]:
    tags = after.get("tags", {})
    return tags if isinstance(tags, dict) else {}


def _sensitivity(after: dict[str, Any]) -> str:
    tags = _tags(after)
    for key in SENSITIVITY_KEYS:
        value = after.get(key, tags.get(key))
        if isinstance(value, str) and value in {"public", "internal", "confidential", "restricted"}:
            return value
    return "internal"


def _public_exposure(after: dict[str, Any]) -> bool:
    if isinstance(after.get("public_exposure"), bool):
        return bool(after["public_exposure"])
    if isinstance(after.get("public"), bool):
        return bool(after["public"])
    acl = after.get("acl")
    if isinstance(acl, str) and acl in PUBLIC_ACL_VALUES:
        return True
    if after.get("policy_public") is True:
        return True
    if after.get("internet_accessible") is True:
        return True
    return False


def _exposure_paths(after: dict[str, Any]) -> list[str]:
    paths = after.get("exposure_paths", [])
    if isinstance(paths, list):
        return [str(item) for item in paths]
    generated: list[str] = []
    if after.get("policy_public") is True:
        generated.append("public_policy")
    if after.get("internet_accessible") is True:
        generated.append("internet_accessible")
    acl = after.get("acl")
    if isinstance(acl, str) and acl in PUBLIC_ACL_VALUES:
        generated.append(f"acl:{acl}")
    return generated


def terraform_plan_to_infra_input(plan: dict[str, Any]) -> dict[str, Any]:
    """Convert a small Terraform-plan-style object into OVK infra input."""
    resources: list[dict[str, Any]] = []
    for index, change in enumerate(plan.get("resource_changes", [])):
        if not isinstance(change, dict):
            continue
        change_body = change.get("change", {})
        if not isinstance(change_body, dict):
            continue
        after = change_body.get("after", {})
        if not isinstance(after, dict):
            continue
        resource_type = str(change.get("type", after.get("resource_type", "unknown_resource")))
        resource_name = str(change.get("name", after.get("name", f"resource_{index}")))
        resource_id = str(after.get("id", f"{resource_type}.{resource_name}"))
        resources.append(
            {
                "resource_id": resource_id,
                "resource_type": resource_type,
                "sensitivity": _sensitivity(after),
                "public_exposure": _public_exposure(after),
                "exposure_paths": _exposure_paths(after),
            }
        )
    return {
        "author_type": plan.get("author_type", "unknown"),
        "agent": plan.get("agent", "unknown"),
        "task": plan.get("task", "terraform_plan_normalization"),
        "resources": resources,
    }
