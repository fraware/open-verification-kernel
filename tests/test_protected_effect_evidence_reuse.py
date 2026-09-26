from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

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
from ovk.core.bundle import make_bundle
from ovk.core.evidence_invariants import check_evidence_bundle_invariants
from ovk.core.evidence_integrity import (
    verify_evidence_digest,
)
from ovk.core.models import VerificationSubject
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity
from ovk.core.protected_effect_evidence import (
    BindingCheckerFingerprint,
    PROTECTED_EFFECT_CHECKER_ID,
    PROTECTED_EFFECT_CHECKER_VERSION,
    ProtectedEffectEvidenceCache,
    ProtectedEffectExecutionFingerprint,
    ProtectedEffectReusePolicy,
    build_execution_fingerprint,
    evaluate_protected_effect_evidence_reuse,
    protected_effect_evaluation_to_evidence,
)
from ovk.core.resource_identity import ResourceIdentityTerm
from ovk.core.result_cache import HardenedResultCache


TEST_SIGNING_KEY = b"protected-effect-reuse-test-key"


def _origin(path: str) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test.protected_effect",
        extractor_version="0.1.0",
    )


def _simple_ir(*, head_sha: str = "head-a") -> AssuranceIR:
    return AssuranceIR(
        subject=VerificationSubject(
            repo="example/app",
            base_sha="base",
            head_sha=head_sha,
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.extractor",
            extractor_version="0.1.0",
        ),
        coverage=AssuranceCoverage(
            status="complete",
            confidence=1.0,
            assumptions=["test extractor faithfully represents the fixture"],
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
                resource_id="r:invoice",
                symbol="invoice_id",
                identity_term=ResourceIdentityTerm.symbol("invoice_id"),
                origin=_origin("routes.py"),
            )
        ],
        effects=[
            EffectRef(
                effect_id="e:refund",
                name="billing.invoice.refund",
                origin=_origin("routes.py"),
            )
        ],
        guards=[
            AuthorizationGuard(
                guard_id="g:refund",
                principal_id="p:user",
                effect_id="e:refund",
                resource_id="r:invoice",
                origin=_origin("routes.py"),
            )
        ],
        protected_effects=[
            ProtectedEffect(
                protected_effect_id="pe:refund",
                principal_id="p:user",
                effect_id="e:refund",
                resource_id="r:invoice",
                origin=_origin("routes.py"),
            )
        ],
        paths=[
            SemanticPath(
                path_id="path:refund",
                entrypoint="POST /refund",
                guard_ids=["g:refund"],
                protected_effect_ids=["pe:refund"],
                origin=_origin("routes.py"),
            )
        ],
    )


def _literal_binding_ir(*, head_sha: str = "head-a") -> AssuranceIR:
    ir = _simple_ir(head_sha=head_sha)
    ir.resources = [
        ResourceRef(
            resource_id="r:authorized",
            symbol="authorized_project",
            identity_term=ResourceIdentityTerm.literal("project-a"),
            origin=_origin("routes.py"),
        ),
        ResourceRef(
            resource_id="r:document",
            symbol="document",
            attribute_terms={
                "project_id": ResourceIdentityTerm.literal("project-a"),
            },
            origin=_origin("routes.py"),
        ),
    ]
    ir.guards[0].resource_id = "r:authorized"
    ir.protected_effects[0].resource_id = "r:document"
    ir.resource_bindings = [
        ResourceBinding(
            binding_id="binding:project-document",
            authorized_resource_id="r:authorized",
            acted_resource_id="r:document",
            relation="equal",
            authorized_projection="identity",
            acted_projection="attribute",
            acted_attribute="project_id",
            origin=_origin("routes.py"),
        )
    ]
    ir.paths[0].binding_ids = ["binding:project-document"]
    return ir


def _fingerprint(evaluation, *, suffix: str = "1") -> ProtectedEffectExecutionFingerprint:
    return build_execution_fingerprint(
        evaluation,
        environment_digest=f"env-{suffix}",
        tool_digest=f"tool-{suffix}",
        worker_image_digest=f"sha256:worker-{suffix}",
        native_execution=True,
    )


def _evidence(ir: AssuranceIR, *, policy_digest: str = "policy-a"):
    evaluation = evaluate_protected_effect_integrity(ir)[0]
    fingerprint = _fingerprint(evaluation)
    evidence = protected_effect_evaluation_to_evidence(
        ir,
        evaluation,
        policy_digest=policy_digest,
        execution_fingerprint=fingerprint,
        signing_key=TEST_SIGNING_KEY,
    )
    return evaluation, fingerprint, evidence


def test_protected_effect_evidence_is_sealed_and_non_controlling() -> None:
    ir = _simple_ir()
    evaluation, fingerprint, evidence = _evidence(ir)

    assert evaluation.status == "pass"
    assert evidence.evidence_digest
    assert verify_evidence_digest(evidence)
    assert evidence.checker_id == PROTECTED_EFFECT_CHECKER_ID
    assert evidence.checker_version == PROTECTED_EFFECT_CHECKER_VERSION
    assert evidence.policy_digest == "policy-a"
    assert evidence.backend_claims[0].required is False
    assert evidence.decision["decision_state"] == "needs_review"
    assert evidence.decision["merge_recommendation"] == "require_human_review"
    assert evidence.decision["controlling_finding_ids"] == []
    assert any(
        item.get("kind") == "protected_effect_execution_fingerprint"
        and item.get("fingerprint_digest") == fingerprint.fingerprint_digest
        for item in evidence.generated_artifacts
    )

    bundle = make_bundle([evidence])
    issues = check_evidence_bundle_invariants(bundle)
    errors = [issue for issue in issues if issue.severity == "error"]
    assert errors == []


def test_literal_binding_evidence_records_observed_checker_provenance() -> None:
    ir = _literal_binding_ir()
    evaluation = evaluate_protected_effect_integrity(ir)[0]

    assert evaluation.status == "pass"
    assert len(evaluation.resource_binding_evidence) == 1
    binding = evaluation.resource_binding_evidence[0]
    assert binding.engine == "structural"
    assert binding.checker_id == "ovk.resource_binding.v1"
    assert binding.checker_version == "0.2.0"

    fingerprint = _fingerprint(evaluation)
    assert fingerprint.binding_checkers == [
        BindingCheckerFingerprint(
            checker_id="ovk.resource_binding.v1",
            checker_version="0.2.0",
            engine="structural",
        )
    ]


def test_declared_binding_checker_fingerprint_must_match_evaluation() -> None:
    ir = _literal_binding_ir()
    evaluation = evaluate_protected_effect_integrity(ir)[0]
    fingerprint = _fingerprint(evaluation).model_copy(
        update={"binding_checkers": []}
    )

    with pytest.raises(ValueError, match="binding_checkers do not match"):
        protected_effect_evaluation_to_evidence(
            ir,
            evaluation,
            policy_digest="policy-a",
            execution_fingerprint=fingerprint,
        )


def test_same_semantics_across_head_sha_is_reusable() -> None:
    base = _simple_ir(head_sha="head-a")
    _, fingerprint, evidence = _evidence(base)
    head = _simple_ir(head_sha="head-b")

    decision = evaluate_protected_effect_evidence_reuse(
        evidence,
        head_ir=head,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint,
        signature_key=TEST_SIGNING_KEY,
    )

    assert decision.eligible is True
    assert decision.reason_codes == []


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        ("policy", "policy_digest_mismatch"),
        ("fingerprint", "runtime_fingerprint_mismatch"),
        ("semantic", "semantic_slice_mismatch"),
    ],
)
def test_reuse_rejects_identity_mismatches(mutation: str, expected_reason: str) -> None:
    base = _simple_ir()
    _, fingerprint, evidence = _evidence(base)
    head = _simple_ir(head_sha="head-b")
    policy_digest = "policy-a"
    current_runtime_fingerprint = fingerprint.runtime_fingerprint

    if mutation == "policy":
        policy_digest = "policy-b"
    elif mutation == "fingerprint":
        current_runtime_fingerprint = fingerprint.runtime_fingerprint.model_copy(
            update={"tool_digest": "different-tool"}
        )
    elif mutation == "semantic":
        head.resources[0].identity_term = ResourceIdentityTerm.symbol("body.invoice_id")

    decision = evaluate_protected_effect_evidence_reuse(
        evidence,
        head_ir=head,
        protected_effect_id="pe:refund",
        policy_digest=policy_digest,
        current_runtime_fingerprint=current_runtime_fingerprint,
        signature_key=TEST_SIGNING_KEY,
    )

    assert decision.eligible is False
    assert expected_reason in decision.reason_codes


def test_reuse_rejects_tampered_revoked_expired_and_signature_required_evidence() -> None:
    ir = _simple_ir()
    _, fingerprint, evidence = _evidence(ir)
    completed = datetime.fromisoformat(evidence.completed_at.replace("Z", "+00:00"))

    tampered = evidence.model_copy(deep=True)
    tampered.backend_claims[0].limits.append("tampered")

    tampered_decision = evaluate_protected_effect_evidence_reuse(
        tampered,
        head_ir=ir,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint,
        signature_key=TEST_SIGNING_KEY,
    )
    assert tampered_decision.eligible is False
    assert "invalid_evidence_digest" in tampered_decision.reason_codes

    revoked = evaluate_protected_effect_evidence_reuse(
        evidence,
        head_ir=ir,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint,
        signature_key=TEST_SIGNING_KEY,
        reuse_policy=ProtectedEffectReusePolicy(
            revoked_evidence_digests=[evidence.evidence_digest],
        ),
    )
    assert revoked.eligible is False
    assert "evidence_revoked" in revoked.reason_codes

    expired = evaluate_protected_effect_evidence_reuse(
        evidence,
        head_ir=ir,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint,
        signature_key=TEST_SIGNING_KEY,
        reuse_policy=ProtectedEffectReusePolicy(max_age_seconds=60),
        now=completed + timedelta(seconds=61),
    )
    assert expired.eligible is False
    assert "evidence_expired" in expired.reason_codes

    unsigned = protected_effect_evaluation_to_evidence(
        ir,
        evaluate_protected_effect_integrity(ir)[0],
        policy_digest="policy-a",
        execution_fingerprint=fingerprint,
    )
    signature_required = evaluate_protected_effect_evidence_reuse(
        unsigned,
        head_ir=ir,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint,
        reuse_policy=ProtectedEffectReusePolicy(require_signature=True),
    )
    assert signature_required.eligible is False
    assert "signature_required" in signature_required.reason_codes


def test_hardened_cache_reissues_new_head_evidence_without_rerunning_checker(
    tmp_path: Path,
) -> None:
    base = _simple_ir(head_sha="head-a")
    _, fingerprint, evidence = _evidence(base)
    cache = ProtectedEffectEvidenceCache(
        HardenedResultCache(tmp_path, ttl_seconds=86400)
    )

    key = cache.put(
        ir=base,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        execution_fingerprint=fingerprint,
        evidence=evidence,
        signature_key=TEST_SIGNING_KEY,
    )
    assert key

    head = _simple_ir(head_sha="head-b")
    reused = cache.reuse_for_head(
        head_ir=head,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint,
        signature_key=TEST_SIGNING_KEY,
    )

    assert reused is not None
    assert reused.subject["head_sha"] == "head-b"
    assert reused.evidence_digest != evidence.evidence_digest
    assert verify_evidence_digest(reused)
    assert reused.backend_claims[0].status.value == "pass"
    assert reused.backend_claims[0].required is False
    reuse_artifact = next(
        item
        for item in reused.generated_artifacts
        if item.get("kind") == "protected_effect_evidence_reuse"
    )
    assert reuse_artifact["prior_evidence_digest"] == evidence.evidence_digest
    assert reuse_artifact["reuse_decision"]["eligible"] is True


def test_hardened_cache_misses_on_semantic_policy_or_fingerprint_change(
    tmp_path: Path,
) -> None:
    base = _simple_ir()
    _, fingerprint, evidence = _evidence(base)
    cache = ProtectedEffectEvidenceCache(HardenedResultCache(tmp_path))
    cache.put(
        ir=base,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        execution_fingerprint=fingerprint,
        evidence=evidence,
        signature_key=TEST_SIGNING_KEY,
    )

    semantic_change = _simple_ir(head_sha="head-b")
    semantic_change.resources[0].identity_term = ResourceIdentityTerm.symbol(
        "body.invoice_id"
    )
    assert cache.reuse_for_head(
        head_ir=semantic_change,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint,
        signature_key=TEST_SIGNING_KEY,
    ) is None

    unchanged = _simple_ir(head_sha="head-b")
    assert cache.reuse_for_head(
        head_ir=unchanged,
        protected_effect_id="pe:refund",
        policy_digest="policy-b",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint,
        signature_key=TEST_SIGNING_KEY,
    ) is None
    assert cache.reuse_for_head(
        head_ir=unchanged,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint.model_copy(
            update={"environment_digest": "env-other"}
        ),
        signature_key=TEST_SIGNING_KEY,
    ) is None


def test_unfingerprinted_evidence_is_sealed_but_never_reusable() -> None:
    ir = _simple_ir()
    evaluation = evaluate_protected_effect_integrity(ir)[0]
    evidence = protected_effect_evaluation_to_evidence(
        ir,
        evaluation,
        policy_digest="policy-a",
        execution_fingerprint=None,
    )
    fingerprint = _fingerprint(evaluation)

    assert verify_evidence_digest(evidence)
    decision = evaluate_protected_effect_evidence_reuse(
        evidence,
        head_ir=ir,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint,
        reuse_policy=ProtectedEffectReusePolicy(require_signature=False),
    )
    assert decision.eligible is False
    assert "missing_or_invalid_execution_fingerprint" in decision.reason_codes



def test_signed_evidence_reuse_requires_correct_signature_key() -> None:
    ir = _simple_ir()
    evaluation = evaluate_protected_effect_integrity(ir)[0]
    fingerprint = _fingerprint(evaluation)
    signing_key = TEST_SIGNING_KEY
    evidence = protected_effect_evaluation_to_evidence(
        ir,
        evaluation,
        policy_digest="policy-a",
        execution_fingerprint=fingerprint,
        signing_key=signing_key,
    )
    assert evidence.signature is not None

    accepted = evaluate_protected_effect_evidence_reuse(
        evidence,
        head_ir=_simple_ir(head_sha="head-b"),
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint,
        signature_key=TEST_SIGNING_KEY,
        reuse_policy=ProtectedEffectReusePolicy(require_signature=True),
        signature_key=signing_key,
    )
    assert accepted.eligible is True

    rejected = evaluate_protected_effect_evidence_reuse(
        evidence,
        head_ir=_simple_ir(head_sha="head-b"),
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint,
        signature_key=TEST_SIGNING_KEY,
        reuse_policy=ProtectedEffectReusePolicy(require_signature=True),
        signature_key=b"wrong-key",
    )
    assert rejected.eligible is False
    assert "invalid_signature" in rejected.reason_codes


def test_semantic_cache_rejects_tampered_evidence_payload(tmp_path: Path) -> None:
    import json

    base = _simple_ir()
    _, fingerprint, evidence = _evidence(base)
    cache = ProtectedEffectEvidenceCache(HardenedResultCache(tmp_path))
    cache.put(
        ir=base,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        execution_fingerprint=fingerprint,
        evidence=evidence,
        signature_key=TEST_SIGNING_KEY,
    )

    path = next((tmp_path / "semantic-evidence").glob("*.json"))
    record = json.loads(path.read_text(encoding="utf-8"))
    record["payload"]["backend_claims"][0]["status"] = "fail"
    path.write_text(json.dumps(record), encoding="utf-8")

    reused = cache.reuse_for_head(
        head_ir=_simple_ir(head_sha="head-b"),
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        current_runtime_fingerprint=fingerprint.runtime_fingerprint,
        signature_key=TEST_SIGNING_KEY,
    )
    assert reused is None
