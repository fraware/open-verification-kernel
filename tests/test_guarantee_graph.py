from __future__ import annotations

from copy import deepcopy

import pytest

from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    AuthorizationGuard,
    EffectRef,
    PrincipalRef,
    ProtectedEffect,
    ResourceRef,
    SemanticOrigin,
    SemanticPath,
)
from ovk.core.guarantee_graph import (
    GuaranteeSelector,
    GuaranteeSpec,
    bind_guarantee,
    build_guarantee_graph_revision,
    compare_guarantee_graphs,
)
from ovk.core.models import VerificationSubject
from ovk.core.resource_identity import ResourceIdentityTerm


def _origin(path: str) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test.extractor",
        extractor_version="0.1.0",
    )


def _ir(*, duplicate_refund: bool = False) -> AssuranceIR:
    resources = [
        ResourceRef(
            resource_id="r:invoice",
            symbol="invoice",
            resource_type="Invoice",
            identity_term=ResourceIdentityTerm.symbol("invoice_id"),
            origin=_origin("billing.py"),
        ),
        ResourceRef(
            resource_id="r:account",
            symbol="account",
            resource_type="Account",
            identity_term=ResourceIdentityTerm.symbol("account_id"),
            origin=_origin("accounts.py"),
        ),
    ]
    effects = [
        EffectRef(
            effect_id="e:refund",
            name="billing.invoice.refund",
            origin=_origin("billing.py"),
        ),
        EffectRef(
            effect_id="e:delete",
            name="identity.account.delete",
            origin=_origin("accounts.py"),
        ),
    ]
    protected = [
        ProtectedEffect(
            protected_effect_id="pe:refund",
            principal_id="p:user",
            effect_id="e:refund",
            resource_id="r:invoice",
            origin=_origin("billing.py"),
        ),
        ProtectedEffect(
            protected_effect_id="pe:delete",
            principal_id="p:user",
            effect_id="e:delete",
            resource_id="r:account",
            origin=_origin("accounts.py"),
        ),
    ]
    guards = [
        AuthorizationGuard(
            guard_id="g:refund",
            principal_id="p:user",
            effect_id="e:refund",
            resource_id="r:invoice",
            origin=_origin("billing.py"),
        ),
        AuthorizationGuard(
            guard_id="g:delete",
            principal_id="p:user",
            effect_id="e:delete",
            resource_id="r:account",
            origin=_origin("accounts.py"),
        ),
    ]
    paths = [
        SemanticPath(
            path_id="path:refund",
            entrypoint="POST /invoices/{invoice_id}/refund",
            guard_ids=["g:refund"],
            protected_effect_ids=["pe:refund"],
            origin=_origin("billing.py"),
        ),
        SemanticPath(
            path_id="path:delete",
            entrypoint="DELETE /account",
            guard_ids=["g:delete"],
            protected_effect_ids=["pe:delete"],
            origin=_origin("accounts.py"),
        ),
    ]

    if duplicate_refund:
        resources.append(
            ResourceRef(
                resource_id="r:invoice-2",
                symbol="other_invoice",
                resource_type="Invoice",
                identity_term=ResourceIdentityTerm.symbol("other_invoice_id"),
                origin=_origin("admin.py"),
            )
        )
        protected.append(
            ProtectedEffect(
                protected_effect_id="pe:refund-2",
                principal_id="p:user",
                effect_id="e:refund",
                resource_id="r:invoice-2",
                origin=_origin("admin.py"),
            )
        )
        guards.append(
            AuthorizationGuard(
                guard_id="g:refund-2",
                principal_id="p:user",
                effect_id="e:refund",
                resource_id="r:invoice-2",
                origin=_origin("admin.py"),
            )
        )
        paths.append(
            SemanticPath(
                path_id="path:refund-2",
                entrypoint="POST /admin/refund",
                guard_ids=["g:refund-2"],
                protected_effect_ids=["pe:refund-2"],
                origin=_origin("admin.py"),
            )
        )

    return AssuranceIR(
        subject=VerificationSubject(
            repo="example/app",
            base_sha="base",
            head_sha="head",
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.extractor",
            extractor_version="0.1.0",
        ),
        coverage=AssuranceCoverage(status="complete", confidence=1.0),
        principals=[
            PrincipalRef(
                principal_id="p:user",
                symbol="user",
                principal_type="User",
                origin=_origin("app.py"),
            )
        ],
        resources=resources,
        effects=effects,
        guards=guards,
        protected_effects=protected,
        paths=paths,
    )


def _refund_spec(**overrides) -> GuaranteeSpec:
    payload = {
        "guarantee_id": "G-REFUND-AUTHZ",
        "statement": "Every invoice refund is authorized for the acted invoice.",
        "selector": GuaranteeSelector(
            effect_name="billing.invoice.refund",
            resource_type="Invoice",
            entrypoint="POST /invoices/{invoice_id}/refund",
        ),
    }
    payload.update(overrides)
    return GuaranteeSpec(**payload)


def test_guarantee_binds_by_semantics_not_revision_sha() -> None:
    base = _ir()
    head = deepcopy(base)
    head.subject.head_sha = "next"

    spec = _refund_spec()
    base_binding = bind_guarantee(base, spec)
    head_binding = bind_guarantee(head, spec)

    assert base_binding.status == "bound"
    assert head_binding.status == "bound"
    assert base_binding.protected_effect_id == "pe:refund"
    assert (
        base_binding.semantic_slice_digest
        == head_binding.semantic_slice_digest
    )

    report = compare_guarantee_graphs(
        base_ir=base,
        head_ir=head,
        base_specs=[spec],
    )
    assert report.transitions[0].kind == "semantic_support_unchanged"
    assert report.transitions[0].dependency_affected is False


def test_semantic_change_requires_fresh_assurance() -> None:
    base = _ir()
    head = deepcopy(base)
    invoice = next(
        resource
        for resource in head.resources
        if resource.resource_id == "r:invoice"
    )
    invoice.identity_term = ResourceIdentityTerm.symbol("body.invoice_id")

    report = compare_guarantee_graphs(
        base_ir=base,
        head_ir=head,
        base_specs=[_refund_spec()],
    )

    transition = report.transitions[0]
    assert transition.kind == "semantic_support_changed"
    assert "fresh assurance" in transition.reason


def test_ambiguous_selector_fails_closed() -> None:
    ir = _ir(duplicate_refund=True)
    spec = GuaranteeSpec(
        guarantee_id="G-REFUND-AMBIGUOUS",
        statement="Refund authorization is preserved.",
        selector=GuaranteeSelector(
            effect_name="billing.invoice.refund",
            resource_type="Invoice",
        ),
    )

    binding = bind_guarantee(ir, spec)

    assert binding.status == "ambiguous"
    assert binding.protected_effect_id is None
    assert binding.semantic_slice_digest is None
    assert binding.matched_protected_effect_ids == ["pe:refund", "pe:refund-2"]


def test_explicit_definition_change_is_not_described_as_strengthening() -> None:
    base = _ir()
    head = deepcopy(base)

    base_spec = _refund_spec()
    head_spec = _refund_spec(
        spec_version="2",
        statement="Every invoice refund is authorized and tenant-scoped.",
    )

    report = compare_guarantee_graphs(
        base_ir=base,
        head_ir=head,
        base_specs=[base_spec],
        head_specs=[head_spec],
    )

    transition = report.transitions[0]
    assert transition.kind == "definition_modified"
    assert "strength" not in transition.reason.lower()


def test_dependency_change_propagates_without_falsely_changing_dependent_semantics() -> None:
    base = _ir()
    head = deepcopy(base)
    invoice = next(
        resource
        for resource in head.resources
        if resource.resource_id == "r:invoice"
    )
    invoice.identity_term = ResourceIdentityTerm.symbol("body.invoice_id")

    refund = _refund_spec()
    account = GuaranteeSpec(
        guarantee_id="G-ACCOUNT-DELETE",
        statement="Account deletion remains authorized.",
        selector=GuaranteeSelector(
            effect_name="identity.account.delete",
            resource_type="Account",
        ),
        dependencies=["G-REFUND-AUTHZ"],
    )

    report = compare_guarantee_graphs(
        base_ir=base,
        head_ir=head,
        base_specs=[refund, account],
    )
    by_id = {item.guarantee_id: item for item in report.transitions}

    assert by_id["G-REFUND-AUTHZ"].kind == "semantic_support_changed"
    assert by_id["G-ACCOUNT-DELETE"].kind == "semantic_support_unchanged"
    assert by_id["G-ACCOUNT-DELETE"].dependency_affected is True
    assert by_id["G-ACCOUNT-DELETE"].dependency_change_roots == [
        "G-REFUND-AUTHZ"
    ]


def test_invalid_dependency_graph_fails_closed() -> None:
    ir = _ir()
    refund = _refund_spec(dependencies=["G-MISSING"])

    with pytest.raises(ValueError, match="unknown dependencies"):
        build_guarantee_graph_revision(ir, [refund])

    g1 = _refund_spec(dependencies=["G-ACCOUNT-DELETE"])
    g2 = GuaranteeSpec(
        guarantee_id="G-ACCOUNT-DELETE",
        statement="Account deletion remains authorized.",
        selector=GuaranteeSelector(effect_name="identity.account.delete"),
        dependencies=["G-REFUND-AUTHZ"],
    )

    with pytest.raises(ValueError, match="dependency cycle"):
        build_guarantee_graph_revision(ir, [g1, g2])
