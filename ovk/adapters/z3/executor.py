"""Optional Z3 executor for authorization obligations."""

from __future__ import annotations

from typing import Any

from ovk.adapters.z3.obligation import AuthorizationObligation


def run_authorization_obligation_with_z3(obligation: AuthorizationObligation) -> dict[str, Any]:
    """Run an authorization violation query with z3-solver when available.

    Result semantics:
    - `fail`: a non-admin reachability violation is satisfiable;
    - `pass`: no violation witness is satisfiable;
    - `unknown`: z3-solver is unavailable or a solver query returns unknown.
    """
    try:
        import z3  # type: ignore
    except Exception:
        return {
            "status": "unknown",
            "reason": "z3-solver is not installed",
            "models": [],
        }

    models: list[dict[str, Any]] = []
    for route_index, route in enumerate(obligation.routes):
        if not route.admin_only_before:
            continue
        for witness_index, witness in enumerate(route.reachable_after):
            solver = z3.Solver()
            admin_route = z3.Bool(f"admin_route_{route_index}")
            reachable = z3.Bool(f"reachable_{route_index}_{witness_index}")
            non_admin = z3.Bool(f"non_admin_{route_index}_{witness_index}")
            violation = z3.And(admin_route, reachable, non_admin)

            solver.add(admin_route == True)
            solver.add(reachable == True)
            solver.add(non_admin == (witness.role != "admin"))
            solver.add(violation)
            result = solver.check()

            if result == z3.sat:
                models.append(
                    {
                        "route": route.path,
                        "user_role": witness.role,
                        "path": witness.via,
                        "model": str(solver.model()),
                        "obligation_id": obligation.obligation_id,
                        "query_polarity": obligation.query_polarity,
                    }
                )
            elif result == z3.unknown:
                return {
                    "status": "unknown",
                    "reason": solver.reason_unknown(),
                    "models": models,
                }

    return {
        "status": "fail" if models else "pass",
        "reason": "violation model found" if models else "no violation model found",
        "models": models,
    }
