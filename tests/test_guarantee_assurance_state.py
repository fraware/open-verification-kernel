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
from ovk.core.guarantee_transport import evaluate_guarantee_transport_admission
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


def test_effect_local_complete_coverage_establishes_guarantee_under_global_partial() -> None:
    ir = _ir()
    ir.coverage.status = "partial"
    ir.coverage.unsupported_constructs = [
        "accounts.py:unrelated_handler:control_flow_outside_v1_subset"
    ]
    refund_path = next(
        path
        for path in ir.paths
        if path.path_id == "path:refund"
    )
    refund_path.coverage_status = "complete"
    refund_path.unsupported_constructs = []
    refund_path.coverage_assumptions = [
        "refund protected-effect prefix is fully represented"
    ]

    evaluation = evaluate_protected_effect_integrity(
        ir,
        protected_effect_ids=["pe:refund"],
    )[0]
    assert evaluation.status == "pass"
    runtime = _runtime()
    fingerprint = build_execution_fingerprint(
        evaluation,
        environment_digest=runtime.environment_digest,
        tool_digest=runtime.tool_digest,
        worker_image_digest=runtime.worker_image_digest,
        native_execution=runtime.native_execution,
    )
    evidence = protected_effect_evaluation_to_evidence(
        ir,
        evaluation,
        policy_digest="policy-a",
        execution_fingerprint=fingerprint,
        signing_key=TEST_KEY,
    )

    assert evidence.coverage is not None
    assert evidence.coverage["status"] == "complete"
    snapshot = build_guarantee_assurance_snapshot(
        ir,
        [_specs()[0]],
        [evidence],
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )

    state = snapshot.state_for("G-REFUND")
    assert state.status == "established"
    assert state.reason_codes == []


def _make_signed_transport_case(tmp_path):
    """Create consecutive signed PE states with a direct evidence-reuse edge."""
    base = _ir(head_sha="base")
    head = _ir(head_sha="head-b")
    spec = _specs()[0]
    evaluation = evaluate_protected_effect_integrity(
        base, protected_effect_ids=["pe:refund"]
    )[0]
    runtime = _runtime()
    fingerprint = build_execution_fingerprint(
        evaluation,
        environment_digest=runtime.environment_digest,
        tool_digest=runtime.tool_digest,
        worker_image_digest=runtime.worker_image_digest,
        native_execution=runtime.native_execution,
    )
    source_evidence = protected_effect_evaluation_to_evidence(
        base,
        evaluation,
        policy_digest="policy-a",
        execution_fingerprint=fingerprint,
        signing_key=TEST_KEY,
    )
    cache = ProtectedEffectEvidenceCache(HardenedResultCache(tmp_path))
    cache.put(
        ir=base,
        protected_effect_id="pe:refund",
        policy_digest="policy-a",
        execution_fingerprint=fingerprint,
        evidence=source_evidence,
        signature_key=TEST_KEY,
    )
    execution = execute_incremental_protected_effect_assurance(
        base,
        head,
        policy_digest="policy-a",
        runtime_fingerprint_provider=lambda _id: runtime,
        evidence_cache=cache,
        signature_key=TEST_KEY,
        signing_key=TEST_KEY,
    )
    assert "pe:refund" in execution.reused_effects
    target_evidence = next(
        item for item in execution.evidence
        if item.intent.get("protected_effect_id") == "pe:refund"
    )
    source_snapshot = build_guarantee_assurance_snapshot(
        base,
        [spec],
        [source_evidence],
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )
    target_snapshot = build_guarantee_assurance_snapshot(
        head,
        [spec],
        [target_evidence],
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )
    assert source_snapshot.state_for("G-REFUND").status == "established"
    assert target_snapshot.state_for("G-REFUND").status == "established"
    return source_snapshot, target_snapshot, source_evidence, target_evidence, head


def _transport_admission(
    source, target, source_evidence, target_evidence, *,
    key=TEST_KEY, source_spec=None, target_spec=None,
):
    return evaluate_guarantee_transport_admission(
        source,
        target,
        guarantee_id="G-REFUND",
        source_spec=source_spec if source_spec is not None else _specs()[0],
        target_spec=target_spec if target_spec is not None else _specs()[0],
        source_evidence=source_evidence,
        target_evidence=target_evidence,
        signature_key=key,
    )


def test_guarantee_transport_admits_direct_signed_same_definition(tmp_path) -> None:
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    decision = _transport_admission(source, target, original, reused)
    assert decision.eligible is True
    assert decision.reason_codes == []
    assert decision.source_definition_digest == decision.target_definition_digest
    assert decision.source_evidence_digest == original.evidence_digest


def test_guarantee_transport_rejects_changed_declaration_even_with_pe_pass(tmp_path) -> None:
    source, _target, original, reused, head = _make_signed_transport_case(tmp_path)
    modified = _specs()[0].model_copy(
        update={"statement": "An edited human-readable statement."}
    )
    target = build_guarantee_assurance_snapshot(
        head,
        [modified],
        [reused],
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )
    # This current-state PASS is *only* about the identical typed PE claim.
    assert target.state_for("G-REFUND").status == "established"
    decision = _transport_admission(
        source, target, original, reused, target_spec=modified
    )
    assert decision.eligible is False
    assert "guarantee_definition_changed" in decision.reason_codes


def test_guarantee_transport_rejects_changed_assumptions(tmp_path) -> None:
    source, _target, original, reused, head = _make_signed_transport_case(tmp_path)
    modified = _specs()[0].model_copy(
        update={"assumptions": ["A newly required operating assumption."]}
    )
    target = build_guarantee_assurance_snapshot(
        head,
        [modified],
        [reused],
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )
    result = _transport_admission(
        source, target, original, reused, target_spec=modified
    )
    assert result.eligible is False
    assert "guarantee_definition_changed" in result.reason_codes


def test_guarantee_transport_rejects_missing_lineage_or_wrong_key(tmp_path) -> None:
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)

    untrusted = _transport_admission(source, target, original, reused, key=None)
    assert untrusted.eligible is False
    assert "source_signature_invalid_or_key_missing" in untrusted.reason_codes

    tampered = reused.model_copy(update={"evidence_digest": "tampered"})
    result = _transport_admission(source, target, original, tampered)
    assert result.eligible is False
    assert "target_evidence_digest_invalid" in result.reason_codes
    assert "target_state_evidence_mismatch" in result.reason_codes

    wrong_prior = reused.model_copy(
        update={
            "change_origin": {
                "source": "reused_sealed_evidence",
                "prior_evidence_digest": "incorrect-source-digest",
                "head_assurance_ir_digest": target.assurance_ir_digest,
            }
        }
    )
    rejected = _transport_admission(source, target, original, wrong_prior)
    assert rejected.eligible is False
    assert "prior_evidence_lineage_mismatch" in rejected.reason_codes


def test_guarantee_transport_rejects_revision_discontinuity(tmp_path) -> None:
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    broken = target.model_copy(update={"subject_base_sha": "other-commit"})
    result = _transport_admission(source, broken, original, reused)
    assert result.eligible is False
    assert "revision_chain_discontinuous" in result.reason_codes


def test_guarantee_transport_does_not_equate_fresh_evidence_with_reuse(tmp_path) -> None:
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    fresh_target = reused.model_copy(
        update={"change_origin": {"source": "assurance_ir"}}
    )
    result = _transport_admission(source, target, original, fresh_target)
    assert result.eligible is False
    assert "target_origin_not_reused" in result.reason_codes


def test_guarantee_transport_rejects_inconsistent_machine_claim_metadata(tmp_path) -> None:
    """Even matching definition digests cannot excuse a divergent typed claim."""
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    state = target.state_for("G-REFUND")
    inconsistent = state.model_copy(
        update={"machine_claim": {
            "guarantee_type": "protected_effect_integrity_v1",
            "selector": {"effect_name": "different.unrelated.effect"},
        }}
    )
    modified = target.model_copy(update={"states": [inconsistent]})
    result = _transport_admission(source, modified, original, reused)
    assert result.eligible is False
    assert "typed_machine_claim_changed" in result.reason_codes


def test_guarantee_transport_rejects_unsigned_or_partial_coverage(tmp_path) -> None:
    """A forged snapshot status cannot substitute for signed checked evidence."""
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    unsigned = reused.model_copy(update={"signature": None})
    result = _transport_admission(source, target, original, unsigned)
    assert result.eligible is False
    assert "target_signature_missing" in result.reason_codes

    partial = reused.model_copy(update={"coverage": {"status": "partial"}})
    result = _transport_admission(source, target, original, partial)
    assert result.eligible is False
    assert "target_coverage_not_complete" in result.reason_codes


def test_guarantee_transport_rejects_snapshot_declaration_forgery(tmp_path) -> None:
    """Matching snapshot digests never override separately supplied declarations."""
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    modified = _specs()[0].model_copy(
        update={"statement": "Different, independently supplied declaration."}
    )
    result = _transport_admission(
        source, target, original, reused, target_spec=modified
    )
    assert result.eligible is False
    assert "target_declaration_digest_mismatch" in result.reason_codes


def test_guarantee_transport_rejects_snapshot_statement_forgery(tmp_path) -> None:
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    state = target.state_for("G-REFUND")
    modified_state = state.model_copy(
        update={"display_statement": "Misleading text, same digest"}
    )
    corrupted = target.model_copy(update={"states": [modified_state]})
    result = _transport_admission(source, corrupted, original, reused)
    assert result.eligible is False
    assert "target_snapshot_statement_mismatch" in result.reason_codes


def test_guarantee_transport_rejects_snapshot_selector_forgery(tmp_path) -> None:
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    state = target.state_for("G-REFUND")
    modified_state = state.model_copy(
        update={
            "machine_claim": {
                "guarantee_type": "protected_effect_integrity_v1",
                "selector": {"effect_name": "unknown.action"},
            }
        }
    )
    corrupted = target.model_copy(update={"states": [modified_state]})
    result = _transport_admission(source, corrupted, original, reused)
    assert result.eligible is False
    assert "target_snapshot_machine_claim_mismatch" in result.reason_codes


def test_guarantee_transport_rejects_mutated_semantic_artifact(tmp_path) -> None:
    """A contradictory semantic artifact invalidates even a signed claim record."""
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    from copy import deepcopy
    from ovk.core.evidence_integrity import seal_evidence

    modified = deepcopy(reused)
    artifacts = [
        item for item in modified.generated_artifacts
        if item.get("kind") == "protected_effect_semantic_slice"
    ]
    assert len(artifacts) == 1
    artifacts[0]["semantic_slice_digest"] = "sha256:wrong"
    # Re-seal to isolate the semantic-admission invariant from cryptographic
    # tampering. The signer is trusted, yet can still produce an inconsistent
    # artifact: the gate must reject it.
    modified = seal_evidence(
        modified,
        key=TEST_KEY,
        policy_digest="policy-a",
        configuration_digest=modified.configuration_digest,
        relevant_file_digests=modified.relevant_file_digests,
    )
    result = _transport_admission(source, target, original, modified)
    assert result.eligible is False
    assert "target_semantic_artifact_mismatch" in result.reason_codes


# Product-facing, non-controlling reviewer scenarios using actual sealed PE
# evidence from this file's existing end-to-end integration fixture.


def _review_for_case(
    source, target, original, reused, *,
    target_spec=None, source_spec=None, key=TEST_KEY,
):
    from ovk.core.guarantee_continuity_review import (
        build_guarantee_continuity_review,
    )

    return build_guarantee_continuity_review(
        source, target, guarantee_id="G-REFUND",
        source_spec=source_spec if source_spec is not None else _specs()[0],
        target_spec=target_spec if target_spec is not None else _specs()[0],
        source_evidence=original,
        target_evidence=reused,
        signature_key=key,
    )


def test_advisory_report_separates_current_claim_and_conditional_reuse(tmp_path):
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    report = _review_for_case(source, target, original, reused)

    assert report.source_typed_claim_status == "established"
    assert report.target_typed_claim_status == "established"
    assert report.target_evidence_origin == "reused"
    assert report.historical_transport == "conditional_candidate"
    assert report.transport_reason_codes == []
    assert report.declared_definition_changed is False
    assert report.declared_machine_claim_changed is False
    assert report.changed_specification_fields == []
    assert report.supplied_source_statement == report.supplied_target_statement
    assert report.snapshot_state_reverified_at_review is False
    assert report.manifest_authority == "not_authenticated"
    assert report.live_temporal_policy == "not_evaluated"
    assert report.source_semantics_refinement == "unproved"
    assert report.production_reliance_authorized is False
    assert report.decision_scope == "advisory_only"
    assert "Production reliance / merge authorization | **NO**" in report.to_markdown()
    assert report.source_evidence_digest == original.evidence_digest
    assert report.target_evidence_digest == reused.evidence_digest


def test_advisory_report_changed_statement_not_historical_reuse(tmp_path):
    source, _, original, reused, head = _make_signed_transport_case(tmp_path)
    changed = _specs()[0].model_copy(
        update={"statement": "A different human-governed refund requirement."}
    )
    target = build_guarantee_assurance_snapshot(
        head, [changed], [reused],
        policy_digest="policy-a", signature_key=TEST_KEY,
    )
    report = _review_for_case(
        source, target, original, reused, target_spec=changed
    )

    # A PASS for the typed PE machine claim does not transport a redefined
    # durable guarantee into the new context.
    assert report.target_typed_claim_status == "established"
    assert report.historical_transport == "not_admitted"
    assert report.declared_definition_changed is True
    assert report.declared_machine_claim_changed is False
    assert report.changed_specification_fields == ["statement"]
    assert report.supplied_source_statement != report.supplied_target_statement
    assert "guarantee_definition_changed" in report.transport_reason_codes
    assert report.next_action == "obtain_fresh_evidence_or_independent_review"
    assert report.production_reliance_authorized is False


def test_advisory_report_changed_assumptions_not_historical_reuse(tmp_path):
    source, _, original, reused, head = _make_signed_transport_case(tmp_path)
    changed = _specs()[0].model_copy(
        update={"assumptions": ["Maintain delegated authorization scope."]}
    )
    target = build_guarantee_assurance_snapshot(
        head, [changed], [reused],
        policy_digest="policy-a", signature_key=TEST_KEY,
    )
    report = _review_for_case(
        source, target, original, reused, target_spec=changed
    )
    assert report.target_typed_claim_status == "established"
    assert report.historical_transport == "not_admitted"
    assert report.declared_definition_changed is True
    assert report.changed_specification_fields == ["assumptions"]
    assert "guarantee_definition_changed" in report.transport_reason_codes
    assert report.production_reliance_authorized is False


def test_advisory_report_refuses_wrong_signature_key(tmp_path):
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    report = _review_for_case(
        source, target, original, reused, key=b"untrusted-demo-key"
    )
    assert report.historical_transport == "not_admitted"
    assert any("signature_invalid" in x for x in report.transport_reason_codes)
    assert report.target_typed_claim_status == "established"
    assert report.production_reliance_authorized is False


def test_advisory_report_untrusted_governance_and_time_never_authorize(tmp_path):
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    report = _review_for_case(source, target, original, reused)
    data = report.model_dump()
    assert data["manifest_authority"] == "not_authenticated"
    assert data["live_temporal_policy"] == "not_evaluated"
    assert data["production_reliance_authorized"] is False
    assert report.next_action == "authenticate_context_and_run_live_policy_checks"


def test_advisory_report_handles_missing_target_state_conservatively(tmp_path):
    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    incomplete = target.model_copy(update={"states": []})
    report = _review_for_case(source, incomplete, original, reused)
    assert report.target_typed_claim_status == "unknown"
    assert report.historical_transport == "not_admitted"
    assert report.production_reliance_authorized is False


def test_advisory_cli_writes_separate_evidence_bound_reports(tmp_path):
    import subprocess
    import sys
    from pathlib import Path

    source, target, original, reused, _ = _make_signed_transport_case(tmp_path)
    inputs = {
        "source-snapshot": source,
        "target-snapshot": target,
        "source-spec": _specs()[0],
        "target-spec": _specs()[0],
        "source-evidence": original,
        "target-evidence": reused,
    }
    argv = []
    for label, value in inputs.items():
        path = tmp_path / f"{label}.json"
        path.write_text(value.model_dump_json(indent=2), encoding="utf-8")
        argv += ["--" + label, str(path)]
    key = tmp_path / "signer.key"
    key.write_bytes(TEST_KEY)
    output = tmp_path / "review-output"
    script = Path(__file__).resolve().parents[1] / "scripts" / "guarantee_continuity_review.py"
    result = subprocess.run(
        [
            sys.executable, str(script), *argv,
            "--guarantee-id", "G-REFUND",
            "--signature-key-file", str(key),
            "--output-dir", str(output),
        ],
        check=True, text=True, capture_output=True,
    )
    assert "Non-controlling review saved" in result.stdout
    import json

    payload = json.loads(
        (output / "continuity-review.json").read_text(encoding="utf-8")
    )
    markdown = (output / "continuity-review.md").read_text(encoding="utf-8")
    assert payload["historical_transport"] == "conditional_candidate"
    assert payload["changed_specification_fields"] == []
    assert payload["production_reliance_authorized"] is False
    assert "advisory only" in markdown
    assert "**NO**" in markdown
    # Refuse to overwrite the same audit record silently.
    again = subprocess.run(
        [
            sys.executable, str(script), *argv,
            "--guarantee-id", "G-REFUND",
            "--signature-key-file", str(key),
            "--output-dir", str(output),
        ],
        text=True, capture_output=True,
    )
    assert again.returncode != 0
    assert payload == json.loads(
        (output / "continuity-review.json").read_text(encoding="utf-8")
    )
