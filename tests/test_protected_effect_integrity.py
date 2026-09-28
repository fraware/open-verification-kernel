from __future__ import annotations

from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    AuthorizationGuard,
    EffectRef,
    PathCondition,
    PrincipalRef,
    ProtectedEffect,
    ResourceBinding,
    ResourceRef,
    SemanticOrigin,
    SemanticPath,
)
from ovk.core.models import VerificationSubject
from ovk.core.protected_effect_integrity import compile_protected_effect_integrity


def _origin(line: int) -> SemanticOrigin:
    return SemanticOrigin(
        path="app.py",
        extractor_id="test.extractor",
        extractor_version="0.1.0",
        source_range={"path": "app.py", "start_line": line, "end_line": line},
    )


def _base_ir(*, guard_resource: str, effect_resource: str, include_binding: bool) -> AssuranceIR:
    bindings = []
    if include_binding:
        bindings.append(
            ResourceBinding(
                binding_id="binding:invoice",
                authorized_resource_id=guard_resource,
                acted_resource_id=effect_resource,
                relation="equal",
                origin=_origin(12),
            )
        )

    return AssuranceIR(
        subject=VerificationSubject(repo="example/payments", base_sha="a", head_sha="b"),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.extractor",
            extractor_version="0.1.0",
        ),
        coverage=AssuranceCoverage(status="complete", confidence=1.0),
        principals=[PrincipalRef(principal_id="p:user", symbol="user", origin=_origin(5))],
        resources=[
            ResourceRef(resource_id="r:authorized", symbol="authorized_invoice", origin=_origin(8)),
            ResourceRef(resource_id="r:acted", symbol="acted_invoice", origin=_origin(10)),
        ],
        effects=[EffectRef(effect_id="e:refund", name="billing.invoice.refund", origin=_origin(10))],
        guards=[
            AuthorizationGuard(
                guard_id="g:refund",
                principal_id="p:user",
                effect_id="e:refund",
                resource_id=guard_resource,
                origin=_origin(9),
            )
        ],
        protected_effects=[
            ProtectedEffect(
                protected_effect_id="pe:refund",
                principal_id="p:user",
                effect_id="e:refund",
                resource_id=effect_resource,
                origin=_origin(10),
            )
        ],
        resource_bindings=bindings,
        paths=[
            SemanticPath(
                path_id="path:refund",
                entrypoint="POST /refund",
                guard_ids=["g:refund"],
                protected_effect_ids=["pe:refund"],
                binding_ids=[item.binding_id for item in bindings],
                origin=_origin(4),
            )
        ],
    )


def _status(obligation, dimension: str) -> str:
    return next(check.status for check in obligation.checks if check.dimension == dimension)


def test_same_resource_is_structurally_established() -> None:
    ir = _base_ir(guard_resource="r:authorized", effect_resource="r:authorized", include_binding=False)
    obligation = compile_protected_effect_integrity(ir)[0]

    assert obligation.structural_status == "established"
    assert _status(obligation, "guard_presence") == "established"
    assert _status(obligation, "principal_binding") == "established"
    assert _status(obligation, "effect_binding") == "established"
    assert _status(obligation, "resource_binding") == "established"


def test_distinct_resources_with_binding_remain_unknown_until_verified() -> None:
    ir = _base_ir(guard_resource="r:authorized", effect_resource="r:acted", include_binding=True)
    obligation = compile_protected_effect_integrity(ir)[0]

    assert obligation.structural_status == "unknown"
    assert _status(obligation, "resource_binding") == "unknown"
    assert obligation.resource_binding_ids == ["binding:invoice"]


def test_distinct_resources_without_binding_are_structurally_violated() -> None:
    ir = _base_ir(guard_resource="r:authorized", effect_resource="r:acted", include_binding=False)
    obligation = compile_protected_effect_integrity(ir)[0]

    assert obligation.structural_status == "violated"
    assert _status(obligation, "resource_binding") == "violated"


def test_missing_guard_on_protected_path_is_violated() -> None:
    ir = _base_ir(guard_resource="r:authorized", effect_resource="r:authorized", include_binding=False)
    ir.paths[0].guard_ids = []

    obligation = compile_protected_effect_integrity(ir)[0]

    assert obligation.structural_status == "violated"
    assert _status(obligation, "guard_presence") == "violated"
    assert _status(obligation, "principal_binding") == "unknown"


def test_guard_for_wrong_principal_is_violated() -> None:
    ir = _base_ir(guard_resource="r:authorized", effect_resource="r:authorized", include_binding=False)
    ir.guards[0].principal_id = "p:other"

    obligation = compile_protected_effect_integrity(ir)[0]

    assert obligation.structural_status == "violated"
    assert _status(obligation, "principal_binding") == "violated"

def test_every_complete_effect_path_requires_a_dominating_guard() -> None:
    ir = _base_ir(
        guard_resource="r:authorized",
        effect_resource="r:authorized",
        include_binding=False,
    )
    ir.paths[0].coverage_status = "complete"
    ir.paths.append(
        SemanticPath(
            path_id="path:unguarded",
            entrypoint="POST /refund",
            guard_ids=[],
            protected_effect_ids=["pe:refund"],
            coverage_status="complete",
            origin=_origin(20),
        )
    )

    obligation = compile_protected_effect_integrity(ir)[0]

    assert obligation.structural_status == "violated"
    assert _status(obligation, "guard_presence") == "violated"
    assert obligation.path_candidate_guard_ids == {
        "path:refund": ["g:refund"],
        "path:unguarded": [],
    }


def test_partial_unguarded_path_preserves_unknown_instead_of_false_fail() -> None:
    ir = _base_ir(
        guard_resource="r:authorized",
        effect_resource="r:authorized",
        include_binding=False,
    )
    ir.paths[0].coverage_status = "complete"
    ir.paths.append(
        SemanticPath(
            path_id="path:partial",
            entrypoint="POST /refund",
            guard_ids=[],
            protected_effect_ids=["pe:refund"],
            coverage_status="partial",
            unsupported_constructs=["branch_outside_profile"],
            origin=_origin(20),
        )
    )

    obligation = compile_protected_effect_integrity(ir)[0]

    assert obligation.structural_status == "unknown"
    assert _status(obligation, "guard_presence") == "unknown"


def test_distinct_valid_guards_may_cover_distinct_paths() -> None:
    ir = _base_ir(
        guard_resource="r:authorized",
        effect_resource="r:authorized",
        include_binding=False,
    )
    ir.paths[0].coverage_status = "complete"
    ir.guards.append(
        AuthorizationGuard(
            guard_id="g:refund-alt",
            principal_id="p:user",
            effect_id="e:refund",
            resource_id="r:authorized",
            origin=_origin(21),
        )
    )
    ir.paths.append(
        SemanticPath(
            path_id="path:alt",
            entrypoint="POST /refund",
            guard_ids=["g:refund-alt"],
            protected_effect_ids=["pe:refund"],
            coverage_status="complete",
            origin=_origin(20),
        )
    )

    obligation = compile_protected_effect_integrity(ir)[0]

    assert obligation.structural_status == "established"
    assert _status(obligation, "guard_presence") == "established"
    assert _status(obligation, "principal_binding") == "established"
    assert _status(obligation, "effect_binding") == "established"
    assert _status(obligation, "guard_effectiveness") == "established"
    assert _status(obligation, "resource_binding") == "established"


def test_conditional_guard_must_dominate_effect_path() -> None:
    ir = _base_ir(
        guard_resource="r:authorized",
        effect_resource="r:authorized",
        include_binding=False,
    )
    ir.paths[0].coverage_status = "complete"
    ir.conditions = [
        PathCondition(
            condition_id="condition:checked",
            expression="check_access",
            origin=_origin(7),
        )
    ]
    ir.guards[0].condition_ids = ["condition:checked"]

    unguarded = compile_protected_effect_integrity(ir)[0]
    assert _status(unguarded, "guard_presence") == "violated"

    ir.paths[0].condition_ids = ["condition:checked"]
    dominated = compile_protected_effect_integrity(ir)[0]

    assert dominated.structural_status == "established"
    assert _status(dominated, "guard_presence") == "established"


def test_unknown_condition_atom_cannot_establish_dominance() -> None:
    ir = _base_ir(
        guard_resource="r:authorized",
        effect_resource="r:authorized",
        include_binding=False,
    )
    ir.paths[0].coverage_status = "complete"
    ir.guards[0].condition_ids = ["condition:unresolved"]
    ir.paths[0].condition_ids = ["condition:unresolved"]

    obligation = compile_protected_effect_integrity(ir)[0]

    assert _status(obligation, "guard_presence") == "violated"

