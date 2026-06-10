"""Privilege escalation obligation model for the Z3 authorization path."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ovk.adapters.z3.counterexample import counterexamples_from_privilege_obligation


PRIVILEGED_ROLES = frozenset({"admin", "owner", "superuser"})


@dataclass(frozen=True)
class PrincipalRoleChange:
    """Role assignment delta for one principal."""

    principal_id: str
    roles_before: frozenset[str]
    roles_after: frozenset[str]


@dataclass(frozen=True)
class PrivilegeEscalationObligation:
    """Backend-independent obligation for privilege escalation."""

    obligation_id: str
    intent_id: str
    principals: list[PrincipalRoleChange]
    privileged_roles: frozenset[str] = field(default_factory=lambda: PRIVILEGED_ROLES)
    assumptions: list[str] = field(default_factory=list)


def build_privilege_escalation_obligation(data: dict[str, Any]) -> PrivilegeEscalationObligation:
    """Build a privilege escalation obligation from a fixture abstraction."""
    principals: list[PrincipalRoleChange] = []
    for item in data.get("principals", []):
        if not isinstance(item, dict):
            continue
        principals.append(
            PrincipalRoleChange(
                principal_id=str(item.get("id", "unknown")),
                roles_before=frozenset(str(role) for role in item.get("roles_before", [])),
                roles_after=frozenset(str(role) for role in item.get("roles_after", [])),
            )
        )
    return PrivilegeEscalationObligation(
        obligation_id="obl-auth-privilege-escalation",
        intent_id="no-privilege-escalation-cedar",
        principals=principals,
        assumptions=[
            "Principal role deltas are supplied by the caller.",
            "A violation exists when a principal gains a privileged role they did not hold before the change.",
        ],
    )


def find_privilege_escalation_counterexamples(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Find privilege escalation counterexamples through the obligation model."""
    obligation = build_privilege_escalation_obligation(data)
    return counterexamples_from_privilege_obligation(obligation)


def evaluate_privilege_escalation(data: dict[str, Any]) -> dict[str, Any]:
    """Evaluate privilege escalation with optional Z3 witness confirmation."""
    obligation = build_privilege_escalation_obligation(data)
    counterexamples = counterexamples_from_privilege_obligation(obligation)
    if not counterexamples:
        return {
            "status": "pass",
            "reason": "no privilege escalation witness found",
            "counterexamples": [],
        }

    try:
        import z3  # type: ignore
    except Exception:
        return {
            "status": "fail",
            "reason": "deterministic privilege escalation witness found",
            "counterexamples": counterexamples,
        }

    confirmed: list[dict[str, Any]] = []
    for index, counterexample in enumerate(counterexamples):
        solver = z3.Solver()
        gained_role = z3.String(f"gained_role_{index}")
        was_privileged_before = z3.Bool(f"was_privileged_before_{index}")
        is_privileged_after = z3.Bool(f"is_privileged_after_{index}")
        role_name = str(counterexample.get("gained_role", "admin"))
        solver.add(gained_role == z3.StringVal(role_name))
        solver.add(was_privileged_before == z3.BoolVal(bool(counterexample.get("was_privileged_before", False))))
        solver.add(is_privileged_after)
        solver.add(z3.Not(was_privileged_before))
        result = solver.check()
        if result == z3.sat:
            model = solver.model()
            witness = dict(counterexample)
            witness["model"] = str(model)
            confirmed.append(witness)
        elif result == z3.unknown:
            return {
                "status": "unknown",
                "reason": solver.reason_unknown(),
                "counterexamples": counterexamples,
            }

    return {
        "status": "fail",
        "reason": "privilege escalation counterexample found",
        "counterexamples": confirmed or counterexamples,
    }
