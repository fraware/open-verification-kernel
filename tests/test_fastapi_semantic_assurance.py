"""FastAPI semantic Assurance IR extraction tests."""

from __future__ import annotations

from ovk.compilers.authorization.fastapi_semantic import (
    AuthorizationCallSpec,
    FastApiSemanticAssuranceCompiler,
    FastApiSemanticConfig,
    PrincipalDependencySpec,
    ProtectedSinkSpec,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.core.protected_effect_integrity import compile_protected_effect_integrity


def _config() -> FastApiSemanticConfig:
    return FastApiSemanticConfig(
        principal_dependencies=[
            PrincipalDependencySpec(dependency="current_user", kind="human"),
        ],
        authorization_calls=[
            AuthorizationCallSpec(
                function="authorize",
                principal_arg=0,
                effect_arg=1,
                resource_arg=2,
                resource_type="invoice",
            ),
        ],
        protected_sinks=[
            ProtectedSinkSpec(
                function="issue_refund",
                effect_name="billing.invoice.refund",
                resource_arg=0,
                resource_type="invoice",
                severity="critical",
            ),
        ],
    )


def _compile(source: str):
    materials = AuthMaterials(
        head_files={"app/routes/refund.py": source},
        repo="example/payments",
        base_revision="base123",
        head_revision="head456",
    )
    return FastApiSemanticAssuranceCompiler(_config()).compile(materials)


def test_linear_handler_extracts_complete_protected_effect_path() -> None:
    ir = _compile(
        """
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/invoices")

@router.post("/{invoice_id}/refund")
def refund(invoice_id: str, user = Depends(current_user)):
    invoice = load_invoice(invoice_id)
    authorize(user, "billing.invoice.refund", invoice)
    issue_refund(invoice)
"""
    )

    assert ir.unknowns == []
    assert len(ir.guards) == 1
    assert len(ir.protected_effects) == 1
    assert len(ir.semantic_paths) == 1
    assert ir.semantic_paths[0].entrypoint == "POST /invoices/{invoice_id}/refund"
    assert ir.semantic_paths[0].guard_refs == [ir.guards[0].guard_id]

    relations = {item.kind: item.relation for item in ir.bindings}
    assert relations == {"principal": "equal", "effect": "equal", "resource": "equal"}

    obligations = compile_protected_effect_integrity(ir)
    assert len(obligations) == 1
    assert obligations[0].coverage.status == "complete"
    requirements = {item["kind"]: item for item in obligations[0].abstraction["binding_requirements"]}
    assert all(item["declared_relation"] == "equal" for item in requirements.values())


def test_resource_mismatch_remains_explicit_unknown_binding() -> None:
    ir = _compile(
        """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.post("/refund")
def refund(user = Depends(current_user)):
    invoice = load_invoice("authorized")
    other_invoice = load_invoice("performed")
    authorize(user, "billing.invoice.refund", invoice)
    issue_refund(other_invoice)
"""
    )

    resource_binding = next(item for item in ir.bindings if item.kind == "resource")
    assert resource_binding.relation == "unknown"
    assert resource_binding.left_ref != resource_binding.right_ref

    obligation = compile_protected_effect_integrity(ir)[0]
    resource_requirement = next(
        item for item in obligation.abstraction["binding_requirements"] if item["kind"] == "resource"
    )
    assert resource_requirement["binding_source"] == "explicit_constraint"
    assert resource_requirement["declared_relation"] == "unknown"


def test_branching_security_logic_downgrades_coverage() -> None:
    ir = _compile(
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

    assert any("unsupported_control_flow:if" in item for item in ir.unknowns)
    assert ir.semantic_paths[0].provenance.coverage == "partial"

    obligation = compile_protected_effect_integrity(ir)[0]
    assert obligation.coverage.status == "partial"
    assert any("unsupported_control_flow:if" in item for item in obligation.coverage.unsupported_constructs)


def test_missing_principal_dependency_is_not_silently_anonymous() -> None:
    ir = _compile(
        """
from fastapi import APIRouter

router = APIRouter()

@router.post("/refund")
def refund(invoice_id: str):
    invoice = load_invoice(invoice_id)
    authorize(user, "billing.invoice.refund", invoice)
    issue_refund(invoice)
"""
    )

    assert any("principal_dependency_missing" in item for item in ir.unknowns)
    sink_principal = next(
        item for item in ir.principals if item.principal_id == ir.protected_effects[0].principal_ref
    )
    assert sink_principal.kind == "unknown"

    principal_binding = next(item for item in ir.bindings if item.kind == "principal")
    assert principal_binding.relation == "unknown"


def test_dynamic_route_path_is_unknown_and_not_claimed() -> None:
    ir = _compile(
        """
from fastapi import APIRouter, Depends

router = APIRouter()
PATH = "/refund"

@router.post(PATH)
def refund(user = Depends(current_user)):
    invoice = load_invoice("x")
    authorize(user, "billing.invoice.refund", invoice)
    issue_refund(invoice)
"""
    )

    assert ir.semantic_paths == []
    assert ir.protected_effects == []
    assert any("dynamic_route_path" in item for item in ir.unknowns)


def test_include_router_mount_is_explicitly_partial_until_modeled() -> None:
    ir = _compile(
        """
from fastapi import APIRouter, Depends, FastAPI

app = FastAPI()
router = APIRouter()

@router.post("/refund")
def refund(user = Depends(current_user)):
    invoice = load_invoice("x")
    authorize(user, "billing.invoice.refund", invoice)
    issue_refund(invoice)

app.include_router(router, prefix="/billing")
"""
    )

    assert any("include_router_mount_not_modeled" in item for item in ir.unknowns)
    # The local route is still extracted, but global mounting is not claimed.
    assert ir.semantic_paths[0].entrypoint == "POST /refund"
