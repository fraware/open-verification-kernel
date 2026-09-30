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
    AuthorizationCutSetEvidence,
    AuthorizationGuard,
    ContractPredicate,
    ContractTerm,
    ContractUse,
    EffectRef,
    FunctionContract,
    InterpretationCompatibilityEvidence,
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
from ovk.core.resource_identity import ResourceInterpretation


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


def test_empty_interpretation_evidence_preserves_legacy_canonical_shape() -> None:
    ir = _ir()

    assert "interpretation_compatibility_evidence" not in ir.canonical_payload()


def test_interpretation_evidence_order_is_digest_stable() -> None:
    ir = _ir()
    common = {
        "input_origin": "request.path.invoice_id",
        "output_type": "InvoiceId",
    }
    left = ResourceInterpretation(
        decoder="authorization.parser",
        **common,
    )
    right = ResourceInterpretation(
        decoder="execution.parser",
        **common,
    )
    ir.interpretation_compatibility_evidence = [
        InterpretationCompatibilityEvidence(
            evidence_id="evidence:b",
            authorized_interpretation=left,
            acted_interpretation=right,
            evidence_kind="interpretation_contract_v1",
            assumptions=["framework-b", "framework-a"],
            origin=_origin("contracts/parser.py", 8),
        ),
        InterpretationCompatibilityEvidence(
            evidence_id="evidence:a",
            authorized_interpretation=left,
            acted_interpretation=right,
            evidence_kind="interpretation_contract_v1",
            assumptions=[],
            origin=_origin("contracts/parser.py", 9),
        ),
    ]
    reordered = deepcopy(ir)
    reordered.interpretation_compatibility_evidence.reverse()
    reordered.interpretation_compatibility_evidence[1].assumptions.reverse()

    assert ir.assurance_ir_digest == reordered.assurance_ir_digest
    payload = ir.canonical_payload()
    assert [
        item["evidence_id"]
        for item in payload["interpretation_compatibility_evidence"]
    ] == ["evidence:a", "evidence:b"]


def test_empty_cut_set_evidence_preserves_prior_canonical_shape() -> None:
    ir = _ir()

    assert "authorization_cut_set_evidence" not in ir.canonical_payload()


def test_cut_set_evidence_order_and_guard_sets_are_digest_stable() -> None:
    ir = _ir()
    evidence = AuthorizationCutSetEvidence(
        evidence_id="cutset:refund",
        protected_effect_id="protected:refund",
        entrypoint="POST /invoices/{invoice_id}/refund",
        guard_ids=["guard:z", "guard:a"],
        guard_cfg_node_ids={
            "guard:z": "stmt:9",
            "guard:a": "stmt:4",
        },
        effect_cfg_node_id="stmt:12",
        control_flow_summary_digest="cfg:refund",
        covers_all_paths=True,
        coverage_status="complete",
        origin=_origin("app/routes.py", 9),
    )
    ir.authorization_cut_set_evidence = [evidence]
    reordered = deepcopy(ir)
    reordered.authorization_cut_set_evidence[0].guard_ids.reverse()
    reordered.authorization_cut_set_evidence[0].guard_cfg_node_ids = {
        "guard:a": "stmt:4",
        "guard:z": "stmt:9",
    }

    assert ir.assurance_ir_digest == reordered.assurance_ir_digest
    payload = ir.canonical_payload()["authorization_cut_set_evidence"][0]
    assert payload["guard_ids"] == ["guard:a", "guard:z"]
    assert list(payload["guard_cfg_node_ids"]) == ["guard:a", "guard:z"]


def test_positive_cut_set_evidence_requires_complete_nonempty_coverage() -> None:
    with pytest.raises(ValueError, match="requires complete coverage"):
        AuthorizationCutSetEvidence(
            evidence_id="cutset:partial",
            protected_effect_id="protected:refund",
            entrypoint="POST /refund",
            guard_ids=["guard:refund"],
            guard_cfg_node_ids={"guard:refund": "stmt:4"},
            effect_cfg_node_id="stmt:8",
            control_flow_summary_digest="cfg:partial",
            covers_all_paths=True,
            coverage_status="partial",
            origin=_origin("app/routes.py", 9),
        )

    with pytest.raises(ValueError, match="requires guards"):
        AuthorizationCutSetEvidence(
            evidence_id="cutset:empty",
            protected_effect_id="protected:refund",
            entrypoint="POST /refund",
            guard_ids=[],
            guard_cfg_node_ids={},
            effect_cfg_node_id="stmt:8",
            control_flow_summary_digest="cfg:complete",
            covers_all_paths=True,
            coverage_status="complete",
            origin=_origin("app/routes.py", 9),
        )


def test_complete_negative_cut_set_requires_counterexample_path() -> None:
    with pytest.raises(ValueError, match="requires an uncovered path"):
        AuthorizationCutSetEvidence(
            evidence_id="cutset:negative",
            protected_effect_id="protected:refund",
            entrypoint="POST /refund",
            guard_ids=["guard:refund"],
            guard_cfg_node_ids={"guard:refund": "stmt:4"},
            effect_cfg_node_id="stmt:8",
            control_flow_summary_digest="cfg:complete",
            covers_all_paths=False,
            coverage_status="complete",
            origin=_origin("app/routes.py", 9),
        )


def test_cut_set_guard_node_map_must_match_guard_ids() -> None:
    with pytest.raises(ValueError, match="node map must match guard_ids"):
        AuthorizationCutSetEvidence(
            evidence_id="cutset:mismatch",
            protected_effect_id="protected:refund",
            entrypoint="POST /refund",
            guard_ids=["guard:a"],
            guard_cfg_node_ids={"guard:b": "stmt:4"},
            effect_cfg_node_id="stmt:8",
            control_flow_summary_digest="cfg:unknown",
            covers_all_paths=False,
            coverage_status="unknown",
            origin=_origin("app/routes.py", 9),
        )


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
