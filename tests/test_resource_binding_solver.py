from __future__ import annotations

import importlib.util

from ovk.adapters.z3.resource_binding import evaluate_resource_binding_with_z3
from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    ResourceBinding,
    ResourceRef,
    SemanticOrigin,
)
from ovk.core.models import VerificationSubject
from ovk.core.resource_identity import ResourceIdentityTerm


def _origin() -> SemanticOrigin:
    return SemanticOrigin(
        path="app.py",
        extractor_id="test.extractor",
        extractor_version="0.1.0",
    )


def _ir(left: ResourceIdentityTerm | None, right: ResourceIdentityTerm | None) -> tuple[AssuranceIR, ResourceBinding]:
    ir = AssuranceIR(
        subject=VerificationSubject(repo="example/payments", base_sha="a", head_sha="b"),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.extractor",
            extractor_version="0.1.0",
        ),
        coverage=AssuranceCoverage(status="complete", confidence=1.0),
        resources=[
            ResourceRef(
                resource_id="r:left",
                symbol="left",
                identity_term=left,
                origin=_origin(),
            ),
            ResourceRef(
                resource_id="r:right",
                symbol="right",
                identity_term=right,
                origin=_origin(),
            ),
        ],
    )
    binding = ResourceBinding(
        binding_id="binding:test",
        authorized_resource_id="r:left",
        acted_resource_id="r:right",
        relation="equal",
        origin=_origin(),
    )
    return ir, binding


def test_equal_literal_resource_identities_pass() -> None:
    ir, binding = _ir(
        ResourceIdentityTerm.literal("invoice-17"),
        ResourceIdentityTerm.literal("invoice-17"),
    )

    result = evaluate_resource_binding_with_z3(ir, binding)

    assert result["status"] == "pass"
    assert result["counterexample"] is None


def test_distinct_literal_resource_identities_fail_without_solver_dependency() -> None:
    ir, binding = _ir(
        ResourceIdentityTerm.literal("invoice-17"),
        ResourceIdentityTerm.literal("invoice-18"),
    )

    result = evaluate_resource_binding_with_z3(ir, binding)

    assert result["status"] == "fail"
    assert result["counterexample"]["authorized_identity"] == "invoice-17"
    assert result["counterexample"]["acted_identity"] == "invoice-18"


def test_missing_resource_identity_is_unknown() -> None:
    ir, binding = _ir(None, ResourceIdentityTerm.symbol("invoice_id"))

    result = evaluate_resource_binding_with_z3(ir, binding)

    assert result["status"] == "unknown"
    assert "missing" in result["reason"]


def test_distinct_symbolic_keys_are_refutable_when_z3_is_available() -> None:
    ir, binding = _ir(
        ResourceIdentityTerm.symbol("invoice_id"),
        ResourceIdentityTerm.symbol("other_invoice_id"),
    )

    result = evaluate_resource_binding_with_z3(ir, binding)

    if importlib.util.find_spec("z3") is None:
        assert result["status"] == "unknown"
        assert result["reason"] == "z3-solver is not installed"
    else:
        assert result["status"] == "fail"
        assert result["counterexample"]["authorized_term"]["value"] == "invoice_id"
        assert result["counterexample"]["acted_term"]["value"] == "other_invoice_id"
        assert result["counterexample"]["symbol_assignment"]
