"""Resource-binding evaluation over restricted identity terms.

The evaluator proves or refutes projection equality only inside the explicit v1
identity model. It does not infer semantics for arbitrary source expressions.

A ResourceBinding names which projection of each resource participates:
- identity: the resource key itself;
- scope: the tenant/workspace/security-domain key attached to that resource.

Result semantics:
- pass: required projection equality is established in the v1 model;
- fail: a counterexample to required equality is satisfiable;
- unknown: modeled projections or the required solver are unavailable.
"""

from __future__ import annotations

from typing import Any

from ovk.core.assurance_ir import AssuranceIR, ResourceBinding, ResourceRef
from ovk.core.resource_identity import ResourceIdentityTerm


def _resource_map(ir: AssuranceIR) -> dict[str, ResourceRef]:
    return {resource.resource_id: resource for resource in ir.resources}


def _projection(
    resource: ResourceRef,
    name: str,
    attribute: str | None,
) -> ResourceIdentityTerm | None:
    if name == "identity":
        return resource.identity_term
    if name == "scope":
        return resource.scope_term
    if name == "attribute" and attribute is not None:
        return resource.attribute_terms.get(attribute)
    return None


def _literal_result(
    left: ResourceIdentityTerm,
    right: ResourceIdentityTerm,
    *,
    left_label: str,
    right_label: str,
) -> dict[str, Any]:
    if left.value == right.value:
        return {
            "status": "pass",
            "reason": f"{left_label} and {right_label} literals are equal",
            "counterexample": None,
        }
    return {
        "status": "fail",
        "reason": f"{left_label} and {right_label} literals differ",
        "counterexample": {
            "authorized_projection": left_label,
            "acted_projection": right_label,
            "authorized_value": left.value,
            "acted_value": right.value,
        },
    }


def evaluate_resource_binding_with_z3(ir: AssuranceIR, binding: ResourceBinding) -> dict[str, Any]:
    """Evaluate one equality-style resource binding under the v1 identity model.

    Both equal and same_tenant reduce to equality between explicitly selected
    projections. The semantic difference is carried by the binding relation and
    by which projections the compiler selected.
    """

    if binding.relation not in {"equal", "same_tenant"}:
        return {
            "status": "unknown",
            "reason": f"resource-binding relation {binding.relation!r} is outside v1 solver semantics",
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

    left = _projection(
        authorized,
        binding.authorized_projection,
        binding.authorized_attribute,
    )
    right = _projection(
        acted,
        binding.acted_projection,
        binding.acted_attribute,
    )
    if left is None or right is None:
        return {
            "status": "unknown",
            "reason": (
                "required resource projection is missing: "
                f"authorized.{binding.authorized_projection} vs acted.{binding.acted_projection}"
            ),
            "counterexample": None,
        }

    left_label = (
        f"authorized.attribute[{binding.authorized_attribute}]"
        if binding.authorized_projection == "attribute"
        else f"authorized.{binding.authorized_projection}"
    )
    right_label = (
        f"acted.attribute[{binding.acted_attribute}]"
        if binding.acted_projection == "attribute"
        else f"acted.{binding.acted_projection}"
    )

    if left == right:
        return {
            "status": "pass",
            "reason": f"{left_label} and {right_label} terms are structurally identical",
            "counterexample": None,
        }

    if left.kind == "literal" and right.kind == "literal":
        return _literal_result(
            left,
            right,
            left_label=left_label,
            right_label=right_label,
        )

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
            "reason": (
                "no counterexample to required projection equality exists "
                "in the v1 resource model"
            ),
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
        "reason": "counterexample to required resource projection equality is satisfiable",
        "counterexample": {
            "relation": binding.relation,
            "authorized_projection": binding.authorized_projection,
            "acted_projection": binding.acted_projection,
            "authorized_attribute": binding.authorized_attribute,
            "acted_attribute": binding.acted_attribute,
            "authorized_term": left.model_dump(mode="json"),
            "acted_term": right.model_dump(mode="json"),
            "symbol_assignment": assignment,
        },
    }
