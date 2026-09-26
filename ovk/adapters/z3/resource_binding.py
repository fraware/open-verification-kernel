"""Resource-binding evaluation over restricted identity terms.

The evaluator proves or refutes equality only inside the explicit v1 identity
model. It does not infer semantics for arbitrary source expressions.

Result semantics:
- pass: equality is established in the v1 model;
- fail: a counterexample to required equality is satisfiable;
- unknown: the IR lacks modeled identity or the required solver is unavailable.
"""

from __future__ import annotations

from typing import Any

from ovk.core.assurance_ir import AssuranceIR, ResourceBinding
from ovk.core.resource_identity import ResourceIdentityTerm


def _resource_map(ir: AssuranceIR):
    return {resource.resource_id: resource for resource in ir.resources}


def _literal_result(left: ResourceIdentityTerm, right: ResourceIdentityTerm) -> dict[str, Any]:
    if left.value == right.value:
        return {
            "status": "pass",
            "reason": "resource identity literals are equal",
            "counterexample": None,
        }
    return {
        "status": "fail",
        "reason": "resource identity literals differ",
        "counterexample": {"authorized_identity": left.value, "acted_identity": right.value},
    }


def evaluate_resource_binding_with_z3(ir: AssuranceIR, binding: ResourceBinding) -> dict[str, Any]:
    """Evaluate one equality binding under the restricted v1 identity model."""

    if binding.relation != "equal":
        return {
            "status": "unknown",
            "reason": f"resource-binding relation {binding.relation!r} is outside v1 equality semantics",
            "counterexample": None,
        }

    resources = _resource_map(ir)
    authorized = resources.get(binding.authorized_resource_id)
    acted = resources.get(binding.acted_resource_id)
    if authorized is None or acted is None:
        return {
            "status": "unknown",
            "reason": "resource binding references an unknown resource",
            "counterexample": None,
        }

    left = authorized.identity_term
    right = acted.identity_term
    if left is None or right is None:
        return {
            "status": "unknown",
            "reason": "resource identity term is missing",
            "counterexample": None,
        }

    if left == right:
        return {
            "status": "pass",
            "reason": "resource identity terms are structurally identical",
            "counterexample": None,
        }

    if left.kind == "literal" and right.kind == "literal":
        return _literal_result(left, right)

    try:
        import z3  # type: ignore
    except Exception:
        return {
            "status": "unknown",
            "reason": "z3-solver is not installed",
            "counterexample": None,
        }

    symbols: dict[str, Any] = {}

    def encode(term: ResourceIdentityTerm):
        if term.kind == "literal":
            return z3.StringVal(term.value)
        symbols.setdefault(term.value, z3.String(f"rid_{len(symbols)}"))
        return symbols[term.value]

    left_expr = encode(left)
    right_expr = encode(right)

    solver = z3.Solver()
    solver.add(left_expr != right_expr)
    result = solver.check()

    if result == z3.unsat:
        return {
            "status": "pass",
            "reason": "no counterexample to required resource equality exists in the v1 identity model",
            "counterexample": None,
        }
    if result == z3.unknown:
        return {
            "status": "unknown",
            "reason": solver.reason_unknown(),
            "counterexample": None,
        }

    model = solver.model()
    assignment: dict[str, str] = {}
    for name, expr in symbols.items():
        value = model.eval(expr, model_completion=True)
        assignment[name] = value.as_string() if hasattr(value, "as_string") else str(value)

    return {
        "status": "fail",
        "reason": "counterexample to required resource equality is satisfiable",
        "counterexample": {
            "authorized_term": left.model_dump(mode="json"),
            "acted_term": right.model_dump(mode="json"),
            "symbol_assignment": assignment,
        },
    }
