from __future__ import annotations

from copy import deepcopy

import pytest

from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    EffectRef,
    PrincipalRef,
    ProtectedEffect,
    ResourceRef,
    SemanticOrigin,
    SemanticPath,
)
from ovk.core.evidence_integrity import (
    integrity_envelope_complete,
    verify_evidence_digest,
)
from ovk.core.incremental_assurance import protected_effect_semantic_digest
from ovk.core.models import VerificationSubject
from ovk.core.protected_effect_evaluation import (
    IntegrityCheck,
    ProtectedEffectIntegrityEvaluation,
    ResourceBindingEvidence,
)
from ovk.core.protected_effect_evidence import (
    protected_effect_evaluation_to_evidence,
)
from ovk.core.resource_identity import ResourceIdentityTerm


def _origin(path: str) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="assurance.fastapi.dependency_effects.ast_v1",
        extractor_version="0.1.0",
    )


def _ir() -> AssuranceIR:
    return AssuranceIR(
        subject=VerificationSubject(
            repo="example/app",
            base_sha="base",
            head_sha="head",
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="assurance.fastapi.dependency_effects.ast_v1",
            extractor_version="0.1.0",
            source_profile_id="assurance.fastapi.dependency_effects.ast_v1",
        ),
        coverage=AssuranceCoverage(
            status="complete",
            confidence=1.0,
            assumptions=["configured dependency semantics are trusted profile input"],
        ),
        principals=[
            PrincipalRef(
                principal_id="p:user",
                symbol="user",
                origin=_origin("routes.py"),
            )
        ],
        resources=[
            ResourceRef(
                resource_id="r:agent",
                symbol="agent_id",
                identity_term=ResourceIdentityTerm.symbol("agent_id"),
                scope_term=ResourceIdentityTerm.symbol("workspace_id"),
                origin=_origin("routes.py"),
            )
        ],
        effects=[
            EffectRef(
                effect_id="e:read",
                name="workspace.agent.read",
                origin=_origin("routes.py"),
            )
        ],
        protected_effects=[
            ProtectedEffect(
                protected_effect_id="pe:read",
                principal_id="p:user",
                effect_id="e:read",
                resource_id="r:agent",
                origin=_origin("routes.py"),
            )
        ],
        paths=[
            SemanticPath(
                path_id="path:read",
                entrypoint="GET /workspaces/{workspace_id}/agents/{agent_id}",
                protected_effect_ids=["pe:read"],
                origin=_origin("routes.py"),
            )
        ],
    )


def _evaluation(ir: AssuranceIR) -> ProtectedEffectIntegrityEvaluation:
    return ProtectedEffectIntegrityEvaluation(
        obligation_id="obligation:pe-read",
        protected_effect_id="pe:read",
        assurance_ir_digest=ir.assurance_ir_digest,
        extraction_coverage="complete",
        status="pass",
        reason="all protected-effect integrity dimensions are established",
        checks=[
            IntegrityCheck(
                dimension="authorization",
                status="established",
                reason="authorization guard established",
            ),
            IntegrityCheck(
                dimension="resource_binding",
                status="established",
                reason="resource binding established",
                evidence_ids=["binding:workspace"],
            ),
        ],
        resource_binding_evidence=[
            ResourceBindingEvidence(
                binding_id="binding:workspace",
                status="pass",
                reason="no counterexample exists",
                checker_id="ovk.resource_binding.z3.v1",
                checker_version="0.1.0",
                native_execution=True,
                tool_version="4.13.4",
            )
        ],
        assumptions=["configured dependency semantics are trusted profile input"],
    )


def test_protected_effect_evidence_is_sealed_and_non_controlling() -> None:
    ir = _ir()
    evaluation = _evaluation(ir)

    evidence = protected_effect_evaluation_to_evidence(ir, evaluation)

    assert evidence.schema_version == "ovk.evidence.v3"
    assert verify_evidence_digest(evidence)
    assert integrity_envelope_complete(evidence)
    assert evidence.checker_id == "ovk.protected_effect_integrity.v1"
    assert evidence.checker_version == "0.1.0"
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.backend_claims[0].required is False
    assert evidence.backend_claims[0].guarantee_type == "protected_effect_integrity_advisory"

    assert evidence.decision["decision_state"] == "needs_review"
    assert evidence.decision["merge_recommendation"] == "require_human_review"
    assert evidence.decision["candidate_claim_status"] == "pass"
    assert evidence.decision["controlling"] is False
    assert evidence.decision["controlling_finding_ids"] == []

    assert evidence.materials is not None
    assert evidence.materials[0]["sha256"] == protected_effect_semantic_digest(
        ir,
        "pe:read",
    )


def test_protected_effect_evidence_retains_subchecker_provenance() -> None:
    ir = _ir()
    evidence = protected_effect_evaluation_to_evidence(ir, _evaluation(ir))

    subcheckers = [
        artifact
        for artifact in evidence.generated_artifacts
        if artifact.get("kind") == "protected_effect_subchecker_provenance"
    ]
    assert subcheckers == [
        {
            "kind": "protected_effect_subchecker_provenance",
            "checker_id": "ovk.resource_binding.z3.v1",
            "checker_version": "0.1.0",
            "tool_version": "4.13.4",
            "native_execution": True,
        }
    ]


def test_shadow_decision_stays_non_controlling_for_fail() -> None:
    ir = _ir()
    evaluation = _evaluation(ir).model_copy(
        update={
            "status": "fail",
            "reason": "resource binding refuted",
        }
    )

    evidence = protected_effect_evaluation_to_evidence(ir, evaluation)

    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision["candidate_claim_status"] == "fail"
    assert evidence.decision["decision_state"] == "needs_review"
    assert evidence.decision["controlling"] is False
    assert verify_evidence_digest(evidence)


def test_builder_rejects_evaluation_from_different_ir() -> None:
    ir = _ir()
    evaluation = _evaluation(ir)
    changed = deepcopy(ir)
    changed.resources[0].scope_term = ResourceIdentityTerm.symbol("other_workspace_id")

    with pytest.raises(ValueError, match="digest does not match"):
        protected_effect_evaluation_to_evidence(changed, evaluation)


def test_semantic_slice_material_changes_with_relevant_semantics() -> None:
    ir = _ir()
    changed = deepcopy(ir)
    changed.resources[0].scope_term = ResourceIdentityTerm.symbol("other_workspace_id")

    first = protected_effect_evaluation_to_evidence(ir, _evaluation(ir))
    second_eval = _evaluation(changed)
    second = protected_effect_evaluation_to_evidence(changed, second_eval)

    assert first.materials is not None
    assert second.materials is not None
    assert first.materials[0]["sha256"] != second.materials[0]["sha256"]
    assert first.input_digest != second.input_digest
