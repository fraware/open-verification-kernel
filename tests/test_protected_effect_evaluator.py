"""End-to-end bounded protected-effect evaluator tests."""

from __future__ import annotations

from types import SimpleNamespace

from ovk.adapters.authorization.deterministic_adapter import AuthorizationDeterministicAdapter
from ovk.adapters.authorization.z3_adapter import Z3NativeAuthorizationAdapter
from ovk.compilers.authorization.fastapi_semantic import (
    AuthorizationCallSpec,
    FastApiSemanticAssuranceCompiler,
    FastApiSemanticConfig,
    PrincipalDependencySpec,
    ProtectedSinkSpec,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.core.deterministic_evaluators import evaluate_deterministic
from ovk.core.execution_models import ExecutionContext
from ovk.core.protected_effect_integrity import compile_protected_effect_integrity


def _config() -> FastApiSemanticConfig:
    return FastApiSemanticConfig(
        principal_dependencies=[PrincipalDependencySpec(dependency="current_user")],
        authorization_calls=[
            AuthorizationCallSpec(
                function="authorize",
                principal_arg=0,
                effect_arg=1,
                resource_arg=2,
                resource_type="invoice",
            )
        ],
        protected_sinks=[
            ProtectedSinkSpec(
                function="issue_refund",
                effect_name="billing.invoice.refund",
                resource_arg=0,
                resource_type="invoice",
                severity="critical",
            )
        ],
    )


def _obligation(source: str):
    materials = AuthMaterials(
        head_files={"app.py": source},
        repo="example/payments",
        base_revision="base",
        head_revision="head",
    )
    ir = FastApiSemanticAssuranceCompiler(_config()).compile(materials)
    return compile_protected_effect_integrity(ir)[0]


def _evaluate(obligation):
    return evaluate_deterministic(
        "authorization-deterministic",
        {
            "input": obligation.abstraction,
            "mode": "deterministic",
            "property_kind": obligation.property_kind,
            "coverage": obligation.coverage.model_dump(mode="json"),
        },
    )


def test_complete_linear_path_is_established() -> None:
    obligation = _obligation(
        """
from fastapi import APIRouter, Depends
router = APIRouter()

@router.post("/refund")
def refund(user = Depends(current_user)):
    invoice = load_invoice("x")
    authorize(user, "billing.invoice.refund", invoice)
    issue_refund(invoice)
"""
    )
    result = _evaluate(obligation)
    assert result["raw_result"]["status"] == "pass"
    assert result["raw_result"]["counterexamples"] == []


def test_missing_guard_is_concrete_violation_on_supported_path() -> None:
    obligation = _obligation(
        """
from fastapi import APIRouter, Depends
router = APIRouter()

@router.post("/refund")
def refund(user = Depends(current_user)):
    invoice = load_invoice("x")
    issue_refund(invoice)
"""
    )
    result = _evaluate(obligation)
    assert result["raw_result"]["status"] == "fail"
    assert result["raw_result"]["counterexamples"][0]["failure_mode"] == "missing_authorization_guard"


def test_unresolved_resource_binding_is_unknown_not_pass() -> None:
    obligation = _obligation(
        """
from fastapi import APIRouter, Depends
router = APIRouter()

@router.post("/refund")
def refund(user = Depends(current_user)):
    authorized_invoice = load_invoice("a")
    performed_invoice = load_invoice("b")
    authorize(user, "billing.invoice.refund", authorized_invoice)
    issue_refund(performed_invoice)
"""
    )
    result = _evaluate(obligation)
    assert result["raw_result"]["status"] == "unknown"
    assert result["raw_result"]["counterexamples"][0]["failure_mode"] == "unresolved_semantic_binding"


def test_partial_control_flow_is_unknown_even_with_matching_names() -> None:
    obligation = _obligation(
        """
from fastapi import APIRouter, Depends
router = APIRouter()

@router.post("/refund")
def refund(user = Depends(current_user)):
    invoice = load_invoice("x")
    if user.is_finance:
        authorize(user, "billing.invoice.refund", invoice)
    issue_refund(invoice)
"""
    )
    result = _evaluate(obligation)
    assert result["raw_result"]["status"] == "unknown"
    assert result["raw_result"]["counterexamples"][0]["failure_mode"] == "incomplete_semantic_coverage"


def test_backend_routing_matches_declared_property_semantics() -> None:
    obligation = _obligation(
        """
from fastapi import APIRouter, Depends
router = APIRouter()

@router.post("/refund")
def refund(user = Depends(current_user)):
    invoice = load_invoice("x")
    authorize(user, "billing.invoice.refund", invoice)
    issue_refund(invoice)
"""
    )
    context = ExecutionContext(subject=obligation.subject)

    deterministic = AuthorizationDeterministicAdapter().can_handle(obligation, context)
    z3 = Z3NativeAuthorizationAdapter().can_handle(obligation, context)

    assert deterministic.support == "supported"
    assert deterministic.guarantee_type == "deterministic_witness"
    assert z3.support == "unsupported"


def test_adapter_payload_preserves_property_and_coverage() -> None:
    obligation = _obligation(
        """
from fastapi import APIRouter, Depends
router = APIRouter()

@router.post("/refund")
def refund(user = Depends(current_user)):
    invoice = load_invoice("x")
    authorize(user, "billing.invoice.refund", invoice)
    issue_refund(invoice)
"""
    )
    adapter = AuthorizationDeterministicAdapter()
    backend_obligation = adapter.compile(
        obligation,
        SimpleNamespace(routing_id="routing-test"),  # type: ignore[arg-type]
    )

    assert "protected_effect_integrity" in adapter.manifest().supported_property_kinds
    assert backend_obligation.payload["property_kind"] == "protected_effect_integrity"
    assert backend_obligation.payload["coverage"]["status"] == "complete"
    assert backend_obligation.payload["input"]["kind"] == "protected_effect_integrity"
