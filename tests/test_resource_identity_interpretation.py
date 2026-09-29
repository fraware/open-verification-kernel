from __future__ import annotations

import importlib.util

import pytest

from ovk.adapters.z3.resource_binding import evaluate_resource_binding_with_z3
from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    ResourceBinding,
    ResourceRef,
    SemanticOrigin,
)
from ovk.core.bundle import content_digest
from ovk.core.models import VerificationSubject
from ovk.core.resource_identity import (
    ResourceIdentityTerm,
    ResourceInterpretation,
)


def _origin() -> SemanticOrigin:
    return SemanticOrigin(
        path="routes.py",
        extractor_id="test.interpretation",
        extractor_version="0.1.0",
    )


def _evaluate(
    authorized: ResourceIdentityTerm,
    acted: ResourceIdentityTerm,
):
    ir = AssuranceIR(
        subject=VerificationSubject(
            repo="example/interpreted-input",
            base_sha="a",
            head_sha="b",
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.interpretation",
            extractor_version="0.1.0",
        ),
        coverage=AssuranceCoverage(
            status="complete",
            confidence=1.0,
        ),
        resources=[
            ResourceRef(
                resource_id="r:authorized",
                symbol="authorized",
                identity_term=authorized,
                origin=_origin(),
            ),
            ResourceRef(
                resource_id="r:acted",
                symbol="acted",
                identity_term=acted,
                origin=_origin(),
            ),
        ],
    )
    binding = ResourceBinding(
        binding_id="binding:interpreted",
        authorized_resource_id="r:authorized",
        acted_resource_id="r:acted",
        relation="equal",
        origin=_origin(),
    )
    return evaluate_resource_binding_with_z3(ir, binding)


def _pydantic_nonnegative(name: str) -> ResourceIdentityTerm:
    return ResourceIdentityTerm.interpreted_symbol(
        name,
        input_origin="request.path.backfill_id",
        decoder="pydantic.TypeAdapter.validate_python:lax",
        output_type="NonNegativeInt",
        constraints=("ge=0",),
    )


def test_plain_term_canonical_payload_preserves_v1_identity() -> None:
    term = ResourceIdentityTerm.symbol("invoice_id")
    payload = {
        "kind": "symbol",
        "value": "invoice_id",
    }

    assert term.canonical_payload() == payload
    assert term.term_id == f"rid:{content_digest(payload)[:16]}"


def test_plain_term_keeps_legacy_shape_inside_assurance_ir_payload() -> None:
    term = ResourceIdentityTerm.symbol("invoice_id")
    ir = AssuranceIR(
        subject=VerificationSubject(
            repo="example/legacy-identity",
            base_sha="a",
            head_sha="b",
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.interpretation",
            extractor_version="0.1.0",
        ),
        coverage=AssuranceCoverage(
            status="complete",
            confidence=1.0,
        ),
        resources=[
            ResourceRef(
                resource_id="r:invoice",
                symbol="invoice_id",
                identity_term=term,
                origin=_origin(),
            )
        ],
    )

    resource = ir.canonical_payload()["resources"][0]
    assert resource["identity_term"] == {
        "kind": "symbol",
        "value": "invoice_id",
    }


def test_interpretation_constraints_are_canonicalized() -> None:
    interpretation = ResourceInterpretation(
        input_origin=" request.path.backfill_id ",
        decoder=" pydantic.TypeAdapter.validate_python:lax ",
        output_type=" NonNegativeInt ",
        constraints=("mode=lax", "ge=0", "ge=0"),
    )

    assert interpretation.input_origin == "request.path.backfill_id"
    assert interpretation.decoder == "pydantic.TypeAdapter.validate_python:lax"
    assert interpretation.output_type == "NonNegativeInt"
    assert interpretation.constraints == ("ge=0", "mode=lax")


def test_literal_cannot_claim_decoder_provenance() -> None:
    with pytest.raises(ValueError):
        ResourceIdentityTerm(
            kind="literal",
            value="17",
            interpretation=ResourceInterpretation(
                input_origin="request.path.id",
                decoder="python.int",
                output_type="int",
            ),
        )


def test_same_input_and_interpretation_pass_despite_local_symbol_rename() -> None:
    result = _evaluate(
        _pydantic_nonnegative("authorized_backfill_id"),
        _pydantic_nonnegative("handler_backfill_id"),
    )

    assert result["status"] == "pass"
    assert result["checker"]["engine"] == "interpretation"


def test_same_input_with_different_decoders_is_unknown() -> None:
    result = _evaluate(
        ResourceIdentityTerm.interpreted_symbol(
            "authorized_backfill_id",
            input_origin="request.path.backfill_id",
            decoder="python.int",
            output_type="int",
        ),
        _pydantic_nonnegative("handler_backfill_id"),
    )

    assert result["status"] == "unknown"
    assert result["checker"]["engine"] == "interpretation-unresolved"
    assert "decoder equivalence requires explicit evidence" in result["reason"]


def test_typed_and_untyped_same_symbol_do_not_collapse_to_pass() -> None:
    result = _evaluate(
        ResourceIdentityTerm.symbol("backfill_id"),
        _pydantic_nonnegative("backfill_id"),
    )

    assert result["status"] == "unknown"
    assert result["checker"]["engine"] == "interpretation-unresolved"


def test_same_local_name_with_different_input_origins_stays_distinct() -> None:
    result = _evaluate(
        ResourceIdentityTerm.interpreted_symbol(
            "resource_id",
            input_origin="request.path.left_id",
            decoder="python.int",
            output_type="int",
        ),
        ResourceIdentityTerm.interpreted_symbol(
            "resource_id",
            input_origin="request.path.right_id",
            decoder="python.int",
            output_type="int",
        ),
    )

    if importlib.util.find_spec("z3") is None:
        assert result["status"] == "unknown"
        assert result["reason"] == "z3-solver is not installed"
    else:
        assert result["status"] == "fail"
        assert result["counterexample"]["authorized_term"]["interpretation"][
            "input_origin"
        ] == "request.path.left_id"
        assert result["counterexample"]["acted_term"]["interpretation"][
            "input_origin"
        ] == "request.path.right_id"
