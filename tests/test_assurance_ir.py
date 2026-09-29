from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import jsonschema
import pytest

from ovk.core.assurance_ir import (
    AssuranceClaim,
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    AuthorizationGuard,
    ContractPredicate,
    ContractTerm,
    ContractUse,
    EffectRef,
    FunctionContract,
    PathCondition,
    PrincipalRef,
    ProtectedEffect,
    ResourceBinding,
    ResourceRef,
    SemanticOrigin,
    SemanticPath,
    compute_assurance_ir_digest,
)
from ovk.core.models import VerificationSubject


def _origin(path: str, line: int) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="fastapi.ast.v2",
        extractor_version="0.1.0",
        source_range={"path": path, "start_line": line, "end_line": line},
    )


def _ir() -> AssuranceIR:
    return AssuranceIR(
        subject=VerificationSubject(
            repo="example/payments",
            base_sha="a" * 40,
            head_sha="b" * 40,
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="fastapi.ast.v2",
            extractor_version="0.1.0",
            source_profile_id="authorization.fastapi.ast_v2",
        ),
        coverage=AssuranceCoverage(
            status="complete",
            confidence=1.0,
            supported_constructs=["Depends", "APIRouter.post"],
            unsupported_constructs=[],
        ),
        principals=[
            PrincipalRef(
                principal_id="principal:user",
                symbol="user",
                principal_type="User",
                origin=_origin("app/routes.py", 11),
            )
        ],
        resources=[
            ResourceRef(
                resource_id="resource:authorized-invoice",
                symbol="invoice",
                resource_type="Invoice",
                origin=_origin("app/routes.py", 14),
            ),
            ResourceRef(
                resource_id="resource:acted-invoice",
                symbol="invoice",
                resource_type="Invoice",
                origin=_origin("app/routes.py", 16),
            ),
        ],
        effects=[
            EffectRef(
                effect_id="effect:refund",
                name="billing.invoice.refund",
                origin=_origin("app/routes.py", 16),
            )
        ],
        conditions=[
            PathCondition(
                condition_id="condition:authenticated",
                expression="user.is_authenticated",
                origin=_origin("app/routes.py", 11),
            )
        ],
        guards=[
            AuthorizationGuard(
                guard_id="guard:refund",
                principal_id="principal:user",
                effect_id="effect:refund",
                resource_id="resource:authorized-invoice",
                condition_ids=["condition:authenticated"],
                origin=_origin("app/routes.py", 15),
            )
        ],
        protected_effects=[
            ProtectedEffect(
                protected_effect_id="protected:refund",
                principal_id="principal:user",
                effect_id="effect:refund",
                resource_id="resource:acted-invoice",
                condition_ids=["condition:authenticated"],
                origin=_origin("app/routes.py", 16),
            )
        ],
        resource_bindings=[
            ResourceBinding(
                binding_id="binding:refund-resource",
                authorized_resource_id="resource:authorized-invoice",
                acted_resource_id="resource:acted-invoice",
                relation="equal",
                origin=_origin("app/routes.py", 16),
            )
        ],
        paths=[
            SemanticPath(
                path_id="path:refund",
                entrypoint="POST /invoices/{invoice_id}/refund",
                guard_ids=["guard:refund"],
                protected_effect_ids=["protected:refund"],
                binding_ids=["binding:refund-resource"],
                condition_ids=["condition:authenticated"],
                origin=_origin("app/routes.py", 9),
            )
        ],
        claims=[
            AssuranceClaim(
                claim_id="claim:refund-integrity",
                claim_kind="protected_effect_integrity",
                statement="Every invoice refund is authorized for the principal, effect, and acted-upon resource.",
                subject_ids=["protected:refund", "guard:refund", "binding:refund-resource"],
                acceptable_guarantees=["smt_refutation_search"],
            )
        ],
        assumptions={
            "framework-routing": "FastAPI routes are represented by the supported AST profile.",
        },
    )


def test_assurance_ir_digest_is_stable_for_set_like_reordering() -> None:
    original = _ir()
    reordered = deepcopy(original)

    reordered.resources.reverse()
    reordered.coverage.supported_constructs.reverse()
    reordered.claims[0].subject_ids.reverse()

    assert original.assurance_ir_digest == reordered.assurance_ir_digest
    assert compute_assurance_ir_digest(original.model_dump(mode="json")) == original.assurance_ir_digest


def test_assurance_ir_digest_changes_when_semantics_change() -> None:
    original = _ir()
    changed = deepcopy(original)
    changed.effects[0].name = "billing.invoice.delete"

    assert changed.assurance_ir_digest != original.assurance_ir_digest


def test_custom_resource_binding_requires_predicate() -> None:
    with pytest.raises(ValueError, match="custom resource binding requires predicate"):
        ResourceBinding(
            binding_id="binding:custom",
            authorized_resource_id="r1",
            acted_resource_id="r2",
            relation="custom",
            origin=_origin("app/routes.py", 20),
        )


def test_semantic_origin_requires_non_empty_extractor_identity() -> None:
    with pytest.raises(ValueError, match="semantic provenance fields must be non-empty"):
        SemanticOrigin(
            path="app/routes.py",
            extractor_id="",
            extractor_version="0.1.0",
        )


def test_assurance_ir_is_descriptive_not_a_merge_decision() -> None:
    payload = _ir().model_dump(mode="json")

    assert "decision" not in payload
    assert payload["coverage"]["status"] == "complete"



def test_assurance_ir_schema_accepts_typed_contracts_and_attribute_bindings() -> None:
    ir = _ir()
    ir.function_contracts = [
        FunctionContract(
            contract_id="contract:document-get",
            qualified_name="DocumentService.get",
            positional_parameters=["document_id"],
            postconditions=[
                ContractPredicate(
                    relation="eq",
                    left=ContractTerm.return_attribute("project_id"),
                    right=ContractTerm.parameter("project_id"),
                )
            ],
            origin=_origin("services/documents.py", 21),
        )
    ]
    ir.resources[1].attribute_terms = {}
    ir.contract_uses = [
        ContractUse(
            use_id="use:document-get",
            contract_id="contract:document-get",
            qualified_name="DocumentService.get",
            resource_id="resource:acted-invoice",
            established_attributes=["project_id"],
            origin=_origin("app/routes.py", 16),
        )
    ]
    ir.resource_bindings[0] = ResourceBinding(
        binding_id="binding:document-project",
        authorized_resource_id="resource:authorized-invoice",
        acted_resource_id="resource:acted-invoice",
        relation="equal",
        authorized_projection="identity",
        acted_projection="attribute",
        acted_attribute="project_id",
        origin=_origin("app/routes.py", 16),
    )

    schema = json.loads(
        Path("schemas/assurance_ir.v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.validate(ir.model_dump(mode="json"), schema)
