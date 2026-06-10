"""Counterexample translation for authorization obligations."""

from __future__ import annotations

from typing import Any

from ovk.adapters.z3.obligation import AuthorizationObligation


FAILURE_MODE = "admin_route_reachable_by_non_admin"
PRIVILEGE_ESCALATION_FAILURE_MODE = "privilege_escalation"


def counterexamples_from_obligation(obligation: AuthorizationObligation) -> list[dict[str, Any]]:
    """Translate authorization reachability witnesses into OVK counterexamples."""
    counterexamples: list[dict[str, Any]] = []
    for route in obligation.routes:
        if not route.admin_only_before:
            continue
        for witness in route.reachable_after:
            if witness.role != "admin":
                counterexamples.append(
                    {
                        "summary": f"Non-admin role {witness.role} can reach admin-only route {route.path}.",
                        "failure_mode": FAILURE_MODE,
                        "route": route.path,
                        "user_role": witness.role,
                        "path": witness.via,
                        "obligation_id": obligation.obligation_id,
                        "query_polarity": obligation.query_polarity,
                    }
                )
    return counterexamples


def counterexamples_from_privilege_obligation(obligation: Any) -> list[dict[str, Any]]:
    """Translate privilege escalation witnesses into OVK counterexamples."""
    counterexamples: list[dict[str, Any]] = []
    for principal in obligation.principals:
        gained = principal.roles_after - principal.roles_before
        privileged_gained = gained & obligation.privileged_roles
        for role in sorted(privileged_gained):
            counterexamples.append(
                {
                    "summary": (
                        f"Principal {principal.principal_id} gained privileged role {role} "
                        "without holding it before the change."
                    ),
                    "failure_mode": PRIVILEGE_ESCALATION_FAILURE_MODE,
                    "principal": principal.principal_id,
                    "gained_role": role,
                    "roles_before": sorted(principal.roles_before),
                    "roles_after": sorted(principal.roles_after),
                    "was_privileged_before": role in principal.roles_before,
                    "obligation_id": obligation.obligation_id,
                }
            )
    return counterexamples
