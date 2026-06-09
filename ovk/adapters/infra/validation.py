"""Validation for infrastructure exposure abstractions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


VALID_SENSITIVITY = {"public", "internal", "confidential", "restricted"}


@dataclass(frozen=True)
class InfraValidationIssue:
    """One validation issue for an infrastructure abstraction."""

    path: str
    message: str
    severity: str = "error"

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "message": self.message, "severity": self.severity}


def validate_infra_input(data: dict[str, Any]) -> list[InfraValidationIssue]:
    """Validate infrastructure exposure input.

    Invalid input cannot support a passing claim.
    """
    resources = data.get("resources")
    if not isinstance(resources, list) or not resources:
        return [InfraValidationIssue("resources", "resources must be a non-empty list")]

    issues: list[InfraValidationIssue] = []
    for index, resource in enumerate(resources):
        path = f"resources[{index}]"
        if not isinstance(resource, dict):
            issues.append(InfraValidationIssue(path, "resource must be an object"))
            continue
        if not isinstance(resource.get("resource_id"), str) or not resource.get("resource_id"):
            issues.append(InfraValidationIssue(f"{path}.resource_id", "resource_id must be a non-empty string"))
        if not isinstance(resource.get("resource_type"), str) or not resource.get("resource_type"):
            issues.append(InfraValidationIssue(f"{path}.resource_type", "resource_type must be a non-empty string"))
        if resource.get("sensitivity") not in VALID_SENSITIVITY:
            issues.append(InfraValidationIssue(f"{path}.sensitivity", "sensitivity is invalid"))
        if not isinstance(resource.get("public_exposure"), bool):
            issues.append(InfraValidationIssue(f"{path}.public_exposure", "public_exposure must be a boolean"))
        exposure_paths = resource.get("exposure_paths", [])
        if not isinstance(exposure_paths, list) or not all(isinstance(item, str) for item in exposure_paths):
            issues.append(InfraValidationIssue(f"{path}.exposure_paths", "exposure_paths must be a list of strings"))
    return issues


def issues_to_diagnostics(issues: list[InfraValidationIssue]) -> list[dict[str, str]]:
    """Render validation issues as OVK diagnostics."""
    return [
        {
            "summary": issue.message,
            "failure_mode": "infrastructure_abstraction_invalid",
            "path": issue.path,
            "severity": issue.severity,
        }
        for issue in issues
    ]
