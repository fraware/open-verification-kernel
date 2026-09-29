from __future__ import annotations

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
from ovk.core.guarantee_assurance_state import (
    GuaranteeAssurancePolicy,
    build_guarantee_assurance_snapshot,
)
from ovk.core.guarantee_graph import GuaranteeSelector, GuaranteeSpec
from ovk.core.models import VerificationSubject
from ovk.core.protected_effect_evaluation import (
    evaluate_protected_effect_integrity,
)
from ovk.core.protected_effect_evidence import (
    ProtectedEffectEvidenceCache,
    ProtectedEffectRuntimeFingerprint,
    build_execution_fingerprint,
    protected_effect_evaluation_to_evidence,
)
from ovk.core.incremental_protected_effect_execution import (
    execute_incremental_protected_effect_assurance,
)
from ovk.core.resource_identity import ResourceIdentityTerm
from ovk.core.result_cache import HardenedResultCache


TEST_KEY = b"guarantee-assurance-state-test-key"


def _origin(path: str) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test.guarantee",
        extractor_version="0.1.0",
    )


def _ir(*, head_sha: str = "head-a") -> AssuranceIR:
    return AssuranceIR(
        subject=VerificationSubject(
            repo="example/guarantee",
            base_sha="base",
            head_sha=head_sha,
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.guarantee",
            extractor_version="0.1.0",
        ),
        coverage=AssuranceCoverage(status="complete", confidence=1.0),
        principals=[
            PrincipalRef(
                principal_id="p:user",
                symbol="user",
                principal_type="User",
                origin=_origin("routes.py"),
            )
        ],
        resources=[
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
        ],
        effects=[
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
        ],
        guards=[
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
        ],
        protected_effects=[
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
        ],
        paths=[
            SemanticPath(
                path_id="path:refund",
                entrypoint="POST /refund",
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
        ],
    )


def _specs(*, with_dependency: bool = False) -> list[GuaranteeSpec]:
    refund = GuaranteeSpec(
        guarantee_id="G-REFUND",
        statement="Refund authorization for the acted invoice.",
        selector=GuaranteeSelector(
            effect_name="billing.invoice.refund",
            resource_type="Invoice",
        ),
    )
    delete = GuaranteeSpec(
        guarantee_id="G-DELETE",
        statement="Account deletion authorization.",
        selector=GuaranteeSelector(
            effect_name="identity.account.delete",
            resource_type="Account",
        ),
        dependencies=["G-REFUND"] if with_dependency else [],
    )
    return [refund, delete]


def _runtime() -> ProtectedEffectRuntimeFingerprint:
    return ProtectedEffectRuntimeFingerprint(
        environment_digest="env:test",
        tool_digest="tool:test",
        worker_image_digest="sha256:worker",
        native_execution=True,
    )


def _fresh_evidence(ir: AssuranceIR):
    evidence = []
    runtime = _runtime()
    for evaluation in evaluate_protected_effect_integrity(ir):
        fingerprint = build_execution_fingerprint(
            evaluation,
            environment_digest=runtime.environment_digest,
            tool_digest=runtime.tool_digest,
            worker_image_digest=runtime.worker_image_digest,
            native_execution=runtime.native_execution,
        )
        evidence.append(
            protected_effect_evaluation_to_evidence(
                ir,
                evaluation,
                policy_digest="policy-a",
                execution_fingerprint=fingerprint,
                signing_key=TEST_KEY,
            )
        )
    return evidence


def test_fresh_signed_pass_establishes_typed_guarantee() -> None:
    ir = _ir()
    snapshot = build_guarantee_assurance_snapshot(
        ir,
        _specs(),
        _fresh_evidence(ir),
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )

    assert snapshot.state_for("G-REFUND").status == "established"
    assert snapshot.state_for("G-REFUND").evidence_origin == "fresh"
    assert snapshot.state_for("G-DELETE").status == "established"
    assert snapshot.state_for("G-REFUND").machine_claim == {
        "guarantee_type": "protected_effect_integrity_v1",
        "selector": {
            "effect_name": "billing.invoice.refund",
            "principal_symbol": None,
            "principal_type": None,
            "resource_symbol": None,
            "resource_type": "Invoice",
            "entrypoint": None,
        },
    }


def test_unchanged_semantics_alone_do_not_establish_guarantee() -> None:
    ir = _ir()
    snapshot = build_guarantee_assurance_snapshot(
        ir,
        _specs(),
        [],
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )

    assert snapshot.state_for("G-REFUND").status == "invalid_evidence"
    assert "missing_current_evidence" in snapshot.state_for("G-REFUND").reason_codes


def test_unsigned_pass_is_rejected_by_default() -> None:
    ir = _ir()
    evaluation = evaluate_protected_effect_integrity(
        ir, protected_effect_ids=["pe:refund"]
    )[0]
    runtime = _runtime()
    fingerprint = build_execution_fingerprint(
        evaluation,
        environment_digest=runtime.environment_digest,
        tool_digest=runtime.tool_digest,
        worker_image_digest=runtime.worker_image_digest,
        native_execution=runtime.native_execution,
    )
    unsigned = protected_effect_evaluation_to_evidence(
        ir,
        evaluation,
        policy_digest="policy-a",
        execution_fingerprint=fingerprint,
    )

    snapshot = build_guarantee_assurance_snapshot(
        ir,
        [_specs()[0]],
        [unsigned],
        policy_digest="policy-a",
    )

    state = snapshot.state_for("G-REFUND")
    assert state.status == "invalid_evidence"
    assert "signature_required" in state.reason_codes

    permissive = build_guarantee_assurance_snapshot(
        ir,
        [_specs()[0]],
        [unsigned],
        policy_digest="policy-a",
        assurance_policy=GuaranteeAssurancePolicy(require_signature=False),
    )
    assert permissive.state_for("G-REFUND").status == "established"


def test_tampered_current_evidence_is_rejected() -> None:
    ir = _ir()
    evidence = _fresh_evidence(ir)
    refund = next(
        item
        for item in evidence
        if item.intent["protected_effect_id"] == "pe:refund"
    )
    tampered = refund.model_copy(
        update={"policy_digest": "attacker-policy"}
    )

    snapshot = build_guarantee_assurance_snapshot(
        ir,
        [_specs()[0]],
        [tampered],
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )

    state = snapshot.state_for("G-REFUND")
    assert state.status == "invalid_evidence"
    assert "invalid_evidence_digest" in state.reason_codes
    assert "policy_digest_mismatch" in state.reason_codes


def test_dependency_prevents_global_established_state() -> None:
    ir = _ir()
    evidence = _fresh_evidence(ir)

    refund = next(
        item
        for item in evidence
        if item.intent["protected_effect_id"] == "pe:refund"
    )
    bad_refund = refund.model_copy(
        update={"evidence_digest": "deadbeef"}
    )
    delete = next(
        item
        for item in evidence
        if item.intent["protected_effect_id"] == "pe:delete"
    )

    snapshot = build_guarantee_assurance_snapshot(
        ir,
        _specs(with_dependency=True),
        [bad_refund, delete],
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )

    refund_state = snapshot.state_for("G-REFUND")
    delete_state = snapshot.state_for("G-DELETE")
    assert refund_state.status == "invalid_evidence"
    assert delete_state.local_status == "established"
    assert delete_state.status == "dependency_unestablished"
    assert delete_state.dependency_statuses == {
        "G-REFUND": "invalid_evidence"
    }


def test_reissued_strictly_reused_evidence_establishes_current_state(
    tmp_path,
) -> None:
    base = _ir(head_sha="head-a")
    head = _ir(head_sha="head-b")
    cache = ProtectedEffectEvidenceCache(HardenedResultCache(tmp_path))

    runtime = _runtime()
    for evaluation in evaluate_protected_effect_integrity(base):
        fingerprint = build_execution_fingerprint(
            evaluation,
            environment_digest=runtime.environment_digest,
            tool_digest=runtime.tool_digest,
            worker_image_digest=runtime.worker_image_digest,
            native_execution=runtime.native_execution,
        )
        evidence = protected_effect_evaluation_to_evidence(
            base,
            evaluation,
            policy_digest="policy-a",
            execution_fingerprint=fingerprint,
            signing_key=TEST_KEY,
        )
        cache.put(
            ir=base,
            protected_effect_id=evaluation.protected_effect_id,
            policy_digest="policy-a",
            execution_fingerprint=fingerprint,
            evidence=evidence,
            signature_key=TEST_KEY,
        )

    execution = execute_incremental_protected_effect_assurance(
        base,
        head,
        policy_digest="policy-a",
        runtime_fingerprint_provider=lambda _effect_id: runtime,
        evidence_cache=cache,
        signature_key=TEST_KEY,
        signing_key=TEST_KEY,
    )
    assert execution.fresh_effects == []
    assert execution.reused_effects == ["pe:delete", "pe:refund"]

    snapshot = build_guarantee_assurance_snapshot(
        head,
        _specs(),
        execution.evidence,
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )

    assert snapshot.state_for("G-REFUND").status == "established"
    assert snapshot.state_for("G-REFUND").evidence_origin == "reused"
    assert snapshot.state_for("G-DELETE").status == "established"
    assert snapshot.state_for("G-DELETE").evidence_origin == "reused"


def test_wrong_head_evidence_does_not_establish_current_guarantee() -> None:
    base = _ir(head_sha="head-a")
    head = _ir(head_sha="head-b")

    snapshot = build_guarantee_assurance_snapshot(
        head,
        [_specs()[0]],
        [
            item
            for item in _fresh_evidence(base)
            if item.intent["protected_effect_id"] == "pe:refund"
        ],
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )

    state = snapshot.state_for("G-REFUND")
    assert state.status == "invalid_evidence"
    assert "head_revision_mismatch" in state.reason_codes
    assert "evaluation_ir_digest_mismatch" in state.reason_codes


def test_unbound_guarantee_is_not_established_by_unrelated_evidence() -> None:
    ir = _ir()
    missing = GuaranteeSpec(
        guarantee_id="G-EXPORT",
        statement="Export authorization.",
        selector=GuaranteeSelector(effect_name="customer.data.export"),
    )

    snapshot = build_guarantee_assurance_snapshot(
        ir,
        [missing],
        _fresh_evidence(ir),
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )

    state = snapshot.state_for("G-EXPORT")
    assert state.status == "unbound"
    assert state.evidence_digest is None
