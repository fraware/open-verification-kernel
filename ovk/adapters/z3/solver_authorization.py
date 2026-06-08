"""Optional Z3-backed authorization reachability encoder.

This module uses z3-solver when installed. If z3 is unavailable, it returns an
explicit unknown result so callers cannot accidentally treat missing solver
coverage as a pass.
"""

from __future__ import annotations

from typing import Any


def evaluate_with_optional_z3(data: dict[str, Any]) -> dict[str, Any]:
    """Check whether a non-admin actor can reach an admin-only route.

    Expected fixture shape matches ``examples/auth_regression``. The encoding is
    intentionally small: each supplied reachability edge is treated as a witness
    candidate. Z3 is used to establish whether a non-admin witness exists.
    """
    try:
        import z3  # type: ignore
    except Exception:
        return {
            "status": "unknown",
            "reason": "z3-solver is not installed",
            "counterexamples": [],
        }

    counterexamples: list[dict[str, Any]] = []
    for idx, route in enumerate(data.get("routes", [])):
        if not route.get("admin_only_before", False):
            continue
        for witness_idx, reachability in enumerate(route.get("reachable_after", [])):
            role = str(reachability.get("role", "unknown"))
            solver = z3.Solver()
            is_admin_route = z3.Bool(f"admin_route_{idx}")
            is_non_admin = z3.Bool(f"non_admin_{idx}_{witness_idx}")
            reachable = z3.Bool(f"reachable_{idx}_{witness_idx}")
            violation = z3.And(is_admin_route, is_non_admin, reachable)
            solver.add(is_admin_route == True)
            solver.add(is_non_admin == (role != "admin"))
            solver.add(reachable == True)
            solver.add(violation)
            result = solver.check()
            if result == z3.sat:
                counterexamples.append(
                    {
                        "summary": f"Non-admin role {role} can reach admin-only route {route.get('path')}.",
                        "failure_mode": "admin_route_reachable_by_non_admin",
                        "route": route.get("path"),
                        "user_role": role,
                        "path": reachability.get("via", []),
                        "model": str(solver.model()),
                    }
                )
            elif result == z3.unknown:
                return {
                    "status": "unknown",
                    "reason": solver.reason_unknown(),
                    "counterexamples": counterexamples,
                }

    return {
        "status": "fail" if counterexamples else "pass",
        "reason": "counterexample found" if counterexamples else "no counterexample found",
        "counterexamples": counterexamples,
    }
