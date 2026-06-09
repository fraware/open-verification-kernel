"""SMT planning helpers for authorization reachability."""

from __future__ import annotations

from dataclasses import dataclass

from ovk.adapters.z3.obligation import AuthorizationObligation


@dataclass(frozen=True)
class SmtClause:
    """A solver-independent clause description."""

    name: str
    expression: str


@dataclass(frozen=True)
class SmtPlan:
    """A solver-independent SMT plan for an authorization obligation."""

    obligation_id: str
    query_polarity: str
    clauses: list[SmtClause]


def build_smt_plan(obligation: AuthorizationObligation) -> SmtPlan:
    """Build a solver-independent plan from an authorization obligation."""
    clauses: list[SmtClause] = []
    for route_index, route in enumerate(obligation.routes):
        if not route.admin_only_before:
            continue
        for witness_index, witness in enumerate(route.reachable_after):
            clause_name = f"route_{route_index}_witness_{witness_index}"
            clauses.append(
                SmtClause(
                    name=clause_name,
                    expression=(
                        f"admin_only_before({route.path}) and "
                        f"role({witness.role}) != admin and "
                        f"reachable_after({route.path}, {witness.role})"
                    ),
                )
            )
    return SmtPlan(
        obligation_id=obligation.obligation_id,
        query_polarity=obligation.query_polarity,
        clauses=clauses,
    )


def smt_plan_to_dict(plan: SmtPlan) -> dict:
    """Serialize an SMT plan for diagnostics and tests."""
    return {
        "obligation_id": plan.obligation_id,
        "query_polarity": plan.query_polarity,
        "clauses": [
            {"name": clause.name, "expression": clause.expression}
            for clause in plan.clauses
        ],
    }
