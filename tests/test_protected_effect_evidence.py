from __future__ import annotations

from copy import deepcopy

from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    AuthorizationGuard,
    EffectRef,
    PrincipalRef,
    ProtectedEffect,
    ResourceBinding,
    ResourceRef,
    SemanticOrigin,
    SemanticPath,
)
from ovk.core.incremental_assurance import protected_effect_semantic_digest
from ovk.core.models import VerificationSubject
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity
from ovk.core.protected_effect_evidence import (
    EvidenceReuseContext,
    protected_effect_evaluation_to_evidence,
    protected_effect_evidence_reuse_decision,
)
from ovk.core.resource_identity import ResourceIdentityTerm


SIGNING_KEY = b"protected-effect-test-signing-key"


def _origin(path: str) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test.extractor",
        extractor_version="0.1.0",
    )


def _ir(*, acted_scope: str = "workspace_id") -> AssuranceIR:
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
                origin=_origin("routes.py"),
            )
        ],
        resources=[
            ResourceRef(
                resource_id="r:authorized",
                symbol="workspace_id",
                identity_term=ResourceIdentityTerm.symbol("workspace_id"),
                origin=_origin("routes.py"),
            ),
            ResourceRef(
                resource_id="r:acted",
                symbol="agent_id",
                identity_term=ResourceIdentityTerm.symbol("agent_id"),
                scope_term=ResourceIdentityTerm.symbol(acted_scope),
                origin=_origin("service.py"),
            ),
        ],
        effects=[
            EffectRef(
                effect_id="e:read",
                name="workspace.agent.read",
                origin=_origin("routes.py"),
            )
        ],
        guards=[
            AuthorizationGuard(
                guard_id="g:workspace",
                principal_id="p:user",
                effect_id="e:read",
                resource_id="r:authorized",
                origin=_origin("routes.py"),
            )
        ],
        protected_effects=[
            ProtectedEffect(
                protected_effect_id="pe:read",
                principal_id="p:user",
                effect_id="e:read",
                resource_id="r:acted",
                origin=_origin("routes.py"),
            )
        ],
        resource_bindings=[
            ResourceBinding(
                binding_id="b:workspace",
                authorized_resource_id="r:authorized",
                acted_resource_id="r:acted",
                relation="same_tenant",
                authorized_projection="identity",
                acted_projection="scope",
                origin=_origin("routes.py"),
            )
        ],
        paths=[
            SemanticPath(
                path_id="path:read",
                entrypoint="GET /workspaces/{workspace_id}/agents/{agent_id}",
                guard_ids=["g:workspace"],
                protected_effect_ids=["pe:read"],
                binding_ids=["b:workspace"],
                origin=_origin("routes.py"),
            )
        ],
    )


def _signed_evidence(ir: AssuranceIR):
    evaluation = evaluate_protected_effect_integrity(ir)[0]
    assert evaluation.status == "pass"
    evidence = protected_effect_evaluation_to_evidence(
        ir,
        evaluation,
        environment_digest="env:ci-image-v1",
        policy_digest="policy:v1",
        configuration_digest="config:v1",
        signing_key=SIGNING_KEY,
    )
    return evaluation, evidence


def _context(ir: AssuranceIR) -> EvidenceReuseContext:
    return EvidenceReuseContext(
        semantic_slice_digest=protected_effect_semantic_digest(ir, "pe:read"),
        environment_digest="env:ci-image-v1",
        policy_digest="policy:v1",
        configuration_digest="config:v1",
    )


def test_protected_effect_evidence_is_sealed_non_controlling_and_reusable_on_exact_match() -> None:
    ir = _ir()
    evaluation, evidence = _signed_evidence(ir)

    assert evidence.schema_version == "ovk.evidence.v3"
    assert evidence.evidence_digest is not None
    assert evidence.signature is not None
    assert evidence.checker_id == "protected-effect-integrity"
    assert evidence.checker_version == "0.1.0"
    assert evidence.decision["controlling"] is False
    assert evidence.backend_claims[0].required is False
    assert evaluation.resource_binding_evidence[0].checker_id == (
        "deterministic.resource_binding.v1"
    )

    decision = protected_effect_evidence_reuse_decision(
        evidence,
        _context(ir),
        signing_key=SIGNING_KEY,
    )

    assert decision.reusable is True
    assert decision.reason == "exact_semantic_and_provenance_match"


def test_unsigned_evidence_is_never_reusable() -> None:
    ir = _ir()
    evaluation = evaluate_protected_effect_integrity(ir)[0]
    evidence = protected_effect_evaluation_to_evidence(
        ir,
        evaluation,
        environment_digest="env:ci-image-v1",
        policy_digest="policy:v1",
        configuration_digest="config:v1",
        signing_key=None,
    )

    decision = protected_effect_evidence_reuse_decision(
        evidence,
        _context(ir),
    )

    assert decision.reusable is False
    assert decision.reason == "unsigned_evidence"


def test_semantic_change_rejects_prior_evidence() -> None:
    ir = _ir()
    _, evidence = _signed_evidence(ir)
    changed = _ir(acted_scope="other_workspace_id")

    decision = protected_effect_evidence_reuse_decision(
        evidence,
        _context(changed),
        signing_key=SIGNING_KEY,
    )

    assert decision.reusable is False
    assert decision.reason == "semantic_slice_mismatch"


def test_environment_policy_configuration_and_checker_changes_each_reject_reuse() -> None:
    ir = _ir()
    _, evidence = _signed_evidence(ir)
    base = _context(ir)

    mutations = [
        ("environment_digest", "env:other", "environment_digest_mismatch"),
        ("policy_digest", "policy:v2", "policy_digest_mismatch"),
        ("configuration_digest", "config:v2", "configuration_digest_mismatch"),
        ("checker_version", "0.2.0", "checker_version_mismatch"),
    ]

    for field, value, reason in mutations:
        context = base.model_copy(update={field: value})
        decision = protected_effect_evidence_reuse_decision(
            evidence,
            context,
            signing_key=SIGNING_KEY,
        )
        assert decision.reusable is False
        assert decision.reason == reason


def test_tampered_evidence_digest_rejects_reuse() -> None:
    ir = _ir()
    _, evidence = _signed_evidence(ir)
    tampered = deepcopy(evidence)
    tampered.generated_artifacts[0]["tampered"] = True

    decision = protected_effect_evidence_reuse_decision(
        tampered,
        _context(ir),
        signing_key=SIGNING_KEY,
    )

    assert decision.reusable is False
    assert decision.reason == "invalid_evidence_digest"


def test_fail_result_is_sealed_but_not_reusable_as_pass_evidence() -> None:
    ir = _ir(acted_scope="other_workspace_id")
    evaluation = evaluate_protected_effect_integrity(ir)[0]
    assert evaluation.status in {"fail", "unknown"}

    evidence = protected_effect_evaluation_to_evidence(
        ir,
        evaluation,
        environment_digest="env:ci-image-v1",
        policy_digest="policy:v1",
        configuration_digest="config:v1",
        signing_key=SIGNING_KEY,
    )

    decision = protected_effect_evidence_reuse_decision(
        evidence,
        _context(ir),
        signing_key=SIGNING_KEY,
    )

    assert decision.reusable is False
    assert decision.reason == "prior_evidence_not_pass"
