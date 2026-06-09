"""Counterexample translation for authorization obligations."""

from __future__ import annotations

from typing import Any

from ovk.adapters.z3.obligation import AuthorizationObligation


FAILURE_MODE = "admin_route_reachable_by_non_admin"


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
