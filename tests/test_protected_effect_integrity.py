"""Protected-effect integrity obligation compilation tests."""

from __future__ import annotations

from ovk.core.assurance_ir import (
    AssuranceIR,
    AuthorizationGuard,
    BindingConstraint,
    EffectRef,
    PrincipalRef,
    ProtectedEffect,
    ResourceRef,
    SemanticPath,
    SourceProvenance,
)
from ovk.core.models import SourceRange, VerificationSubject
from ovk.core.protected_effect_integrity import compile_protected_effect_integrity


def _subject() -> VerificationSubject:
    return VerificationSubject(repo="example/payments", base_sha="base", head_sha="head")


def _p(path: str, *, coverage: str = "complete") -> SourceProvenance:
    return SourceProvenance(
        extractor_id="authorization.fastapi.semantic_v2",
        extractor_version="0.1.0",
        subject=_subject(),
        source_ranges=[SourceRange(path=path, start_line=1, end_line=4)],
        coverage=coverage,
    )


def _ir(*, same_resource: bool = True, unknowns: list[str] | None = None) -> AssuranceIR:
    principal = PrincipalRef(principal_id="p.user", kind="human", provenance=_p("auth.py"))
    effect = EffectRef(effect_id="e.refund", name="billing.invoice.refund", provenance=_p("billing.py"))
    authorized = ResourceRef(resource_id="r.authorized", resource_type="invoice", provenance=_p("route.py"))
    performed_id = authorized.resource_id if same_resource else "r.performed"
    resources = [authorized]
    if not same_resource:
        resources.append(ResourceRef(resource_id=performed_id, resource_type="invoice", provenance=_p("route.py")))

    guard = AuthorizationGuard(
        guard_id="g.refund",
        principal_ref=principal.principal_id,
        effect_ref=effect.effect_id,
        resource_ref=authorized.resource_id,
        provenance=_p("route.py"),
    )
    protected = ProtectedEffect(
        protected_effect_id="pe.refund",
        principal_ref=principal.principal_id,
        effect_ref=effect.effect_id,
        resource_ref=performed_id,
        sink="billing.issue_refund",
        severity="critical",
        provenance=_p("route.py"),
    )
    path = SemanticPath(
        path_id="path.refund",
        entrypoint="POST /refund",
        protected_effect_ref=protected.protected_effect_id,
        guard_refs=[guard.guard_id],
        call_chain=["handler", "authorize", "issue_refund"],
        provenance=_p("route.py"),
    )
    bindings = []
    if not same_resource:
        bindings = [
            BindingConstraint(
                binding_id="b.resource",
                kind="resource",
                left_ref=authorized.resource_id,
                right_ref=performed_id,
                relation="unknown",
                expression="authorized_invoice == modified_invoice",
                provenance=_p("route.py"),
            )
        ]

    return AssuranceIR(
        subject=_subject(),
        principals=[principal],
        resources=resources,
        effects=[effect],
        guards=[guard],
        protected_effects=[protected],
        bindings=bindings,
        semantic_paths=[path],
        unknowns=unknowns or [],
    )


def test_compiles_one_obligation_per_semantic_path() -> None:
    obligations = compile_protected_effect_integrity(_ir())
    assert len(obligations) == 1
    obligation = obligations[0]
    assert obligation.property_kind == "protected_effect_integrity"
    assert obligation.lane == "authorization"
    assert obligation.severity.value == "critical"
    assert obligation.abstraction["path_id"] == "path.refund"
    assert obligation.materials[0].uri.startswith("ovk-material:assurance-ir/")


def test_identity_bindings_are_explicit() -> None:
    obligation = compile_protected_effect_integrity(_ir())[0]
    requirements = obligation.abstraction["binding_requirements"]
    assert {item["kind"] for item in requirements} == {"principal", "effect", "resource"}
    assert all(item["binding_source"] == "identity" for item in requirements)
    assert all(item["declared_relation"] == "equal" for item in requirements)


def test_nonidentical_resource_uses_explicit_binding_constraint() -> None:
    obligation = compile_protected_effect_integrity(_ir(same_resource=False))[0]
    resource = next(
        item for item in obligation.abstraction["binding_requirements"] if item["kind"] == "resource"
    )
    assert resource["binding_source"] == "explicit_constraint"
    assert resource["binding_id"] == "b.resource"
    assert resource["declared_relation"] == "unknown"
    assert resource["expression"] == "authorized_invoice == modified_invoice"


def test_ir_unknowns_downgrade_coverage() -> None:
    obligation = compile_protected_effect_integrity(_ir(unknowns=["dynamic_resource_lookup"]))[0]
    assert obligation.coverage.status == "partial"
    assert "dynamic_resource_lookup" in obligation.coverage.unsupported_constructs


def test_obligation_identity_is_deterministic() -> None:
    first = compile_protected_effect_integrity(_ir())[0]
    second = compile_protected_effect_integrity(_ir())[0]
    assert first.obligation_id == second.obligation_id
    assert first.abstraction_digest == second.abstraction_digest


def test_semantic_change_changes_obligation_identity() -> None:
    base = compile_protected_effect_integrity(_ir())[0]
    changed_ir = _ir()
    path = changed_ir.semantic_paths[0].model_copy(
        update={"call_chain": ["handler", "authorize", "legacy_adapter", "issue_refund"]}
    )
    changed_ir = changed_ir.model_copy(update={"semantic_paths": [path]})
    changed = compile_protected_effect_integrity(changed_ir)[0]
    assert base.obligation_id != changed.obligation_id
