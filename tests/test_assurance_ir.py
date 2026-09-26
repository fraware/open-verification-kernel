"""Assurance IR identity and reference-integrity tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ovk.core.assurance_ir import (
    AssuranceClaim,
    AssuranceIR,
    AuthorizationGuard,
    BindingConstraint,
    EffectRef,
    PrincipalRef,
    ProtectedEffect,
    ResourceRef,
    SemanticPath,
    SourceProvenance,
    compute_assurance_ir_digest,
    seal_assurance_ir,
)
from ovk.core.models import SourceRange, VerificationSubject


def _subject() -> VerificationSubject:
    return VerificationSubject(repo="example/payments", base_sha="base123", head_sha="head456", pull_request=17)


def _provenance(path: str, start: int = 1, end: int = 4) -> SourceProvenance:
    return SourceProvenance(
        extractor_id="authorization.fastapi.semantic_v2",
        extractor_version="0.1.0",
        subject=_subject(),
        source_ranges=[SourceRange(path=path, start_line=start, end_line=end)],
        coverage="complete",
    )


def _claim(**extra) -> AssuranceClaim:
    return AssuranceClaim(
        claim_id="claim.refund.authorization",
        property_kind="protected_effect_integrity",
        statement="Refunds must use the same principal, effect, and invoice resource that were authorized.",
        origin="human",
        semantic_refs=[],
        acceptable_guarantees=["smt_refutation_search"],
        provenance=_provenance(".verification/intents/refund.yml"),
        **extra,
    )


def _ir() -> AssuranceIR:
    principal = PrincipalRef(
        principal_id="principal.current_user",
        kind="human",
        expression="current_user",
        provenance=_provenance("app/auth.py"),
    )
    authorized_resource = ResourceRef(
        resource_id="resource.invoice.authorized",
        resource_type="invoice",
        expression="invoice",
        provenance=_provenance("app/routes/refund.py", 10, 11),
    )
    performed_resource = ResourceRef(
        resource_id="resource.invoice.performed",
        resource_type="invoice",
        expression="invoice",
        provenance=_provenance("app/routes/refund.py", 12, 13),
    )
    effect = EffectRef(
        effect_id="effect.invoice.refund",
        name="billing.invoice.refund",
        operation="refund",
        provenance=_provenance("app/routes/refund.py", 8, 13),
    )
    guard = AuthorizationGuard(
        guard_id="guard.refund",
        principal_ref=principal.principal_id,
        effect_ref=effect.effect_id,
        resource_ref=authorized_resource.resource_id,
        decision_expression='authorize(user, "refund", invoice)',
        provenance=_provenance("app/routes/refund.py", 10, 10),
    )
    protected = ProtectedEffect(
        protected_effect_id="protected.refund",
        principal_ref=principal.principal_id,
        effect_ref=effect.effect_id,
        resource_ref=performed_resource.resource_id,
        sink="billing.issue_refund",
        severity="critical",
        provenance=_provenance("app/routes/refund.py", 12, 12),
    )
    binding = BindingConstraint(
        binding_id="binding.refund.resource",
        kind="resource",
        left_ref=authorized_resource.resource_id,
        right_ref=performed_resource.resource_id,
        relation="equal",
        provenance=_provenance("app/routes/refund.py", 10, 12),
    )
    path = SemanticPath(
        path_id="path.refund",
        entrypoint="POST /invoices/{invoice_id}/refund",
        protected_effect_ref=protected.protected_effect_id,
        guard_refs=[guard.guard_id],
        call_chain=["refund", "authorize", "issue_refund"],
        provenance=_provenance("app/routes/refund.py", 7, 13),
    )
    claim = _claim().model_copy(
        update={
            "semantic_refs": [
                principal.principal_id,
                effect.effect_id,
                authorized_resource.resource_id,
                performed_resource.resource_id,
                guard.guard_id,
                protected.protected_effect_id,
                binding.binding_id,
                path.path_id,
            ]
        }
    )
    return AssuranceIR(
        subject=_subject(),
        principals=[principal],
        resources=[authorized_resource, performed_resource],
        effects=[effect],
        guards=[guard],
        protected_effects=[protected],
        bindings=[binding],
        semantic_paths=[path],
        claims=[claim],
        assumptions=["FastAPI dependency injection follows the supported source profile."],
    )


def test_assurance_ir_round_trip() -> None:
    ir = _ir()
    payload = ir.model_dump(mode="json")
    assert AssuranceIR.model_validate(payload).model_dump(mode="json") == payload


def test_claim_cannot_self_assert_approval() -> None:
    payload = _claim().model_dump(mode="json")
    payload["approval_status"] = "approved"
    with pytest.raises(ValidationError, match="approval_status"):
        AssuranceClaim.model_validate(payload)


def test_digest_is_order_insensitive_for_set_like_collections() -> None:
    ir = _ir()
    assert compute_assurance_ir_digest(ir) == compute_assurance_ir_digest(
        ir.model_copy(update={"resources": list(reversed(ir.resources))})
    )


def test_digest_preserves_semantic_path_call_order() -> None:
    ir = _ir()
    path = ir.semantic_paths[0]
    changed = ir.model_copy(
        update={"semantic_paths": [path.model_copy(update={"call_chain": list(reversed(path.call_chain))})]}
    )
    assert compute_assurance_ir_digest(ir) != compute_assurance_ir_digest(changed)


def test_sealed_ir_rejects_semantic_tampering() -> None:
    sealed = seal_assurance_ir(_ir())
    payload = sealed.model_dump(mode="json")
    payload["effects"][0]["name"] = "billing.invoice.delete"
    with pytest.raises(ValidationError, match="ir_digest"):
        AssuranceIR.model_validate(payload)


def test_effect_name_must_be_namespaced() -> None:
    with pytest.raises(ValidationError, match="namespaced"):
        EffectRef(effect_id="effect.refund", name="refund", provenance=_provenance("app/routes/refund.py"))


def test_unknown_guard_reference_is_rejected() -> None:
    ir = _ir()
    path = ir.semantic_paths[0].model_copy(update={"guard_refs": ["guard.missing"]})
    with pytest.raises(ValidationError, match="unknown guard"):
        AssuranceIR.model_validate({**ir.model_dump(mode="json"), "semantic_paths": [path.model_dump(mode="json")]})


def test_binding_reference_must_match_binding_kind() -> None:
    ir = _ir()
    invalid = BindingConstraint(
        binding_id="binding.invalid",
        kind="resource",
        left_ref=ir.principals[0].principal_id,
        right_ref=ir.resources[0].resource_id,
        provenance=_provenance("app/routes/refund.py"),
    )
    with pytest.raises(ValidationError, match="unknown resource"):
        AssuranceIR.model_validate({**ir.model_dump(mode="json"), "bindings": [invalid.model_dump(mode="json")]})


def test_claim_reference_must_exist() -> None:
    ir = _ir()
    claim = ir.claims[0].model_copy(update={"semantic_refs": ["missing.semantic.object"]})
    with pytest.raises(ValidationError, match="unknown semantic object"):
        AssuranceIR.model_validate({**ir.model_dump(mode="json"), "claims": [claim.model_dump(mode="json")]})
