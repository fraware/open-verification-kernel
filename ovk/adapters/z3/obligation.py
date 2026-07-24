"""Authorization proof-obligation model for the Z3 path."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


QueryPolarity = Literal["find_violation", "prove_no_violation"]


@dataclass(frozen=True)
class RouteReachabilityWitness:
    """A candidate reachability witness after a change."""

    role: str
    via: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AuthorizationRoute:
    """A route relevant to authorization reachability."""

    path: str
    admin_only_before: bool
    admin_only_after: bool
    reachable_after: list[RouteReachabilityWitness] = field(default_factory=list)


@dataclass(frozen=True)
class AuthorizationObligation:
    """Backend-independent obligation for admin-route reachability."""

    obligation_id: str
    intent_id: str
    query_polarity: QueryPolarity
    routes: list[AuthorizationRoute]
    assumptions: list[str]


def build_authorization_obligation(data: dict[str, Any]) -> AuthorizationObligation:
    """Build an authorization obligation from the current fixture abstraction."""
    routes: list[AuthorizationRoute] = []
    for route in data.get("routes", []):
        witnesses = [
            RouteReachabilityWitness(
                role=str(item.get("role", "unknown")),
                via=[str(step) for step in item.get("via", [])],
            )
            for item in route.get("reachable_after", [])
            if isinstance(item, dict)
        ]
        routes.append(
            AuthorizationRoute(
                path=str(route.get("path", "unknown")),
                admin_only_before=bool(route.get("admin_only_before", False)),
                admin_only_after=bool(route.get("admin_only_after", False)),
                reachable_after=witnesses,
            )
        )

    return AuthorizationObligation(
        obligation_id="obl-auth-admin-route-reachability",
        intent_id="no-admin-route-bypass",
        query_polarity="find_violation",
        routes=routes,
        assumptions=[
            "Route reachability abstraction is supplied by the caller.",
            "A violation exists when a non-admin role reaches a route marked admin-only before the change.",
        ],
    )


def obligation_to_dict(obligation: AuthorizationObligation) -> dict[str, Any]:
    """Serialize an obligation for evidence and debugging."""
    return {
        "obligation_id": obligation.obligation_id,
        "intent_id": obligation.intent_id,
        "query_polarity": obligation.query_polarity,
        "routes": [
            {
                "path": route.path,
                "admin_only_before": route.admin_only_before,
                "admin_only_after": route.admin_only_after,
                "reachable_after": [{"role": witness.role, "via": witness.via} for witness in route.reachable_after],
            }
            for route in obligation.routes
        ],
        "assumptions": obligation.assumptions,
    }
