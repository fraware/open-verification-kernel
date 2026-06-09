"""Validation for authorization route abstractions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AuthorizationValidationIssue:
    """One validation issue for an authorization abstraction."""

    path: str
    message: str
    severity: str = "error"

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "message": self.message, "severity": self.severity}


def validate_authorization_input(data: dict[str, Any]) -> list[AuthorizationValidationIssue]:
    """Validate the route abstraction used by the authorization obligation path.

    The validator is conservative. Missing route metadata is an error because it
    prevents OVK from making a trustworthy pass claim.
    """
    issues: list[AuthorizationValidationIssue] = []
    routes = data.get("routes")
    if not isinstance(routes, list) or not routes:
        return [
            AuthorizationValidationIssue(
                path="routes",
                message="routes must be a non-empty list",
            )
        ]

    for route_index, route in enumerate(routes):
        route_path = f"routes[{route_index}]"
        if not isinstance(route, dict):
            issues.append(AuthorizationValidationIssue(route_path, "route must be an object"))
            continue

        if not isinstance(route.get("path"), str) or not route.get("path"):
            issues.append(AuthorizationValidationIssue(f"{route_path}.path", "path must be a non-empty string"))

        if not isinstance(route.get("admin_only_before"), bool):
            issues.append(
                AuthorizationValidationIssue(
                    f"{route_path}.admin_only_before",
                    "admin_only_before must be a boolean",
                )
            )

        if not isinstance(route.get("admin_only_after"), bool):
            issues.append(
                AuthorizationValidationIssue(
                    f"{route_path}.admin_only_after",
                    "admin_only_after must be a boolean",
                )
            )

        reachable_after = route.get("reachable_after")
        if not isinstance(reachable_after, list):
            issues.append(
                AuthorizationValidationIssue(
                    f"{route_path}.reachable_after",
                    "reachable_after must be a list of witness objects",
                )
            )
            continue

        for witness_index, witness in enumerate(reachable_after):
            witness_path = f"{route_path}.reachable_after[{witness_index}]"
            if not isinstance(witness, dict):
                issues.append(AuthorizationValidationIssue(witness_path, "witness must be an object"))
                continue
            if not isinstance(witness.get("role"), str) or not witness.get("role"):
                issues.append(
                    AuthorizationValidationIssue(
                        f"{witness_path}.role",
                        "role must be a non-empty string",
                    )
                )
            via = witness.get("via", [])
            if not isinstance(via, list) or not all(isinstance(step, str) for step in via):
                issues.append(
                    AuthorizationValidationIssue(
                        f"{witness_path}.via",
                        "via must be a list of strings when supplied",
                    )
                )

    return issues


def issues_to_counterexamples(issues: list[AuthorizationValidationIssue]) -> list[dict[str, str]]:
    """Render validation issues as OVK counterexample-like diagnostics."""
    return [
        {
            "summary": issue.message,
            "failure_mode": "authorization_abstraction_invalid",
            "path": issue.path,
            "severity": issue.severity,
        }
        for issue in issues
    ]
