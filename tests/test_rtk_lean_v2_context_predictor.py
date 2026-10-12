"""Differential development checks of the pre-oracle Lean RTK context SUT.

These fixtures are invented inputs to stress the predictor's declared model.
They are not independent native Lean oracle cases or empirical validation.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from experiments.rtk.lean_v2_context_predictor import (
    LeanContextManifest,
    LeanHistoricalEvidence,
    LeanSupportNode,
    LeanTransportInput,
    evaluate_lean_transport,
    make_prediction_bundle,
)
from experiments.rtk.lean_v2_preoracle import (
    FrozenCohort,
    FrozenLeanCase,
    digest,
    make_commitment,
)

A, B, C, D, E, F = ("a" * 64, "b" * 64, "c" * 64,
                    "d" * 64, "e" * 64, "f" * 64)
SOURCE, TARGET = "1" * 40, "2" * 40


def manifest(*, statement=A, checker=B, policy=C, axiom=D,
             nodes=None, roots=None, complete=True, environment=E,
             extractor=F, config=A, revision=SOURCE):
    if nodes is None:
        nodes = [
            LeanSupportNode(
                symbol="TrustedPremise", semantic_sha256=B,
            ),
            LeanSupportNode(
                symbol="IndependentHelper", semantic_sha256=C,
            ),
            LeanSupportNode(
                symbol="MyTheorem",
                semantic_sha256=D,
                dependencies=["TrustedPremise"],
            ),
        ]
    return LeanContextManifest(
        schema_version="rtk.lean_v2.context_manifest.v1",
        repository="public/lean-project",
        revision_sha=revision,
        theorem_source_path="Src.lean",
        theorem_symbol="MyTheorem",
        statement_sha256=statement,
        checker_binary_sha256=checker,
        checker_configuration_sha256=config,
        environment_sha256=environment,
        relying_policy_sha256=policy,
        trusted_axioms_sha256=axiom,
        source_extractor_sha256=extractor,
        support_claimed_complete=complete,
        root_symbols=["MyTheorem"] if roots is None else roots,
        support_nodes=nodes,
    )


def inputs(source=None, target=None, *, state="active", accepted="ACCEPTED"):
    source = source or manifest()
    target = target or manifest(revision=TARGET)
    case = FrozenLeanCase(
        case_id="lean-case-1",
        transition_id="transition-1",
        repository="public/lean-project",
        source_sha=SOURCE,
        target_sha=TARGET,
        source_path="Src.lean",
        target_path="Src.lean",
        theorem_name="MyTheorem",
        source_evidence_sha256=F,
        source_native_acceptance_sha256=E,
        source_context_sha256=digest(source),
        target_claim_sha256=target.statement_sha256,
        target_context_sha256=digest(target),
        selection_rank=0,
    )
    return LeanTransportInput(
        case=case, source=source, target=target,
        evidence=LeanHistoricalEvidence(
            source_proof_sha256=F,
            native_acceptance_receipt_sha256=E,
            source_acceptance=accepted,
            admissibility=state,
        ),
    )


def test_same_declared_context_is_conditional_valid_without_native_oracle():
    record = inputs()
    result = evaluate_lean_transport(record)
    assert result.verdict == "VALID"
    assert result.reason_codes == []
    assert result.evidence_reuse_conditionally_eligible is True
    assert result.formal_soundness_established is False
    assert result.native_oracle_consulted is False
    assert result.external_manifest_authority_verified is False
    assert result.revalidation_obligations == []


def test_irrelevant_node_change_does_not_invalidate_proof_closure():
    target_nodes = [
        LeanSupportNode(symbol="TrustedPremise", semantic_sha256=B),
        LeanSupportNode(symbol="IndependentHelper", semantic_sha256=F),
        LeanSupportNode(
            symbol="MyTheorem", semantic_sha256=D,
            dependencies=["TrustedPremise"],
        ),
    ]
    decision = evaluate_lean_transport(inputs(target=manifest(revision=TARGET, nodes=target_nodes)))
    assert decision.verdict == "VALID"
    assert decision.source_support_sha256 == decision.target_support_sha256


def test_change_in_transitive_support_demands_revalidation():
    target_nodes = [
        LeanSupportNode(symbol="TrustedPremise", semantic_sha256=F),
        LeanSupportNode(symbol="IndependentHelper", semantic_sha256=C),
        LeanSupportNode(
            symbol="MyTheorem", semantic_sha256=D,
            dependencies=["TrustedPremise"],
        ),
    ]
    decision = evaluate_lean_transport(inputs(target=manifest(revision=TARGET, nodes=target_nodes)))
    assert decision.verdict == "REVALIDATION_REQUIRED"
    assert "transitive_support_changed" in decision.reason_codes
    assert "TrustedPremise" in decision.affected_support_symbols
    assert "MyTheorem" in decision.affected_support_symbols
    assert "fresh_native_check_target_claim" in decision.revalidation_obligations


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"statement": F}, "statement_changed"),
        ({"checker": F}, "checker_changed"),
        ({"policy": F}, "relying_policy_changed"),
        ({"axiom": F}, "axiom_context_changed"),
        ({"environment": F}, "environment_changed"),
        ({"extractor": E}, "extractor_changed"),
        ({"config": F}, "checker_configuration_changed"),
    ],
)
def test_affecting_typed_claim_checker_and_policy_invalidates_reuse(change, reason):
    result = evaluate_lean_transport(inputs(target=manifest(revision=TARGET, **change)))
    assert result.verdict == "REVALIDATION_REQUIRED"
    assert reason in result.reason_codes
    assert result.evidence_reuse_conditionally_eligible is False


@pytest.mark.parametrize(
    ("source", "target", "state", "accepted", "reason"),
    [
        (None, manifest(revision=TARGET, complete=False), "active", "ACCEPTED",
         "support_completeness_unestablished"),
        (None, None, "unknown", "ACCEPTED",
         "prior_evidence_admissibility_unknown"),
        (None, None, "active", "NOT_ESTABLISHED",
         "source_native_acceptance_not_established"),
        (
            None,
            manifest(revision=TARGET, nodes=[
                LeanSupportNode(symbol="MyTheorem", semantic_sha256=A,
                                dependencies=["AbsentDependency"])
            ]),
            "active", "ACCEPTED", "support_missing_support_node",
        ),
        (
            None,
            manifest(revision=TARGET, nodes=[
                LeanSupportNode(
                    symbol="MyTheorem", semantic_sha256=A,
                    dependencies=["Other"]
                ),
                LeanSupportNode(
                    symbol="Other", semantic_sha256=B,
                    dependencies=["MyTheorem"]
                ),
            ]),
            "active", "ACCEPTED", "support_dependency_cycle",
        ),
    ],
)
def test_missing_or_unverifiable_material_abstains(source, target, state, accepted, reason):
    record = inputs(
        source=source, target=target, state=state, accepted=accepted,
    )
    decision = evaluate_lean_transport(record)
    assert decision.verdict == "UNRESOLVED"
    assert reason in decision.reason_codes
    assert decision.evidence_reuse_conditionally_eligible is False


@pytest.mark.parametrize("state", ["revoked", "expired"])
def test_expired_or_revoked_source_is_not_reused(state):
    result = evaluate_lean_transport(inputs(state=state))
    assert result.verdict == "REVALIDATION_REQUIRED"
    assert "prior_evidence_" + state in result.reason_codes


def test_reordered_dependency_manifest_has_same_support_identity():
    orig = manifest()
    flipped = manifest(revision=TARGET, nodes=list(reversed(orig.support_nodes)))
    result = evaluate_lean_transport(inputs(source=orig, target=flipped))
    assert result.verdict == "VALID"


def test_context_mutation_without_case_rebinding_fails_closed():
    record = inputs()
    forged = record.model_copy(update={
        "target": manifest(revision=TARGET, checker=F),
    })
    with pytest.raises(ValueError, match="frozen case"):
        evaluate_lean_transport(forged)


def test_inconsistent_nested_pydantic_model_copy_is_revalidated():
    record = inputs()
    modified = record.target.model_copy(
        update={"checker_binary_sha256": "invalid-digest"}
    )
    forged = record.model_copy(update={"target": modified})
    with pytest.raises(ValidationError):
        evaluate_lean_transport(forged)


def test_prediction_bundle_consumes_only_matching_precommitted_cases():
    record = inputs()
    cohort = FrozenCohort(
        schema_version="rtk.lean_v2.preoracle_cohort.v1",
        selection_rule_sha256=A,
        source_adapter_id="lean-source@v2",
        oracle_adapter_id="native-replay@v2",
        oracle_commit=TARGET,
        sut_adapter_id="rtk.lean_context.v1-development",
        sut_commit=SOURCE,
        cases=[record.case],
    )
    bundle, decisions = make_prediction_bundle(
        cohort, [record], sut_commit=SOURCE,
    )
    assert [x.verdict for x in decisions] == ["VALID"]
    assert bundle.predictions[0].verdict == "VALID"
    commitment = make_commitment(
        cohort, bundle, private_nonce_hex="8d" * 32
    )
    assert commitment.prediction_count == 1
    assert commitment.cohort_sha256 == digest(cohort)
    with pytest.raises(ValueError, match="SUT identity"):
        make_prediction_bundle(cohort, [record], sut_commit=TARGET)


def test_predictor_rejects_oracle_verdict_on_input_surface():
    record = inputs()
    data = record.model_dump()
    data["target_native_oracle"] = "ACCEPTED"
    with pytest.raises(ValidationError):
        LeanTransportInput.model_validate(data)


def test_manifest_declared_revision_path_and_repository_must_match_frozen_case():
    record = inputs()
    for update in (
        {"revision_sha": SOURCE},
        {"theorem_source_path": "OtherFile.lean"},
        {"repository": "attacker/swapped-repository"},
    ):
        modified = record.target.model_copy(update=update)
        tampered = record.model_copy(update={"target": modified})
        with pytest.raises(ValueError, match="frozen case"):
            evaluate_lean_transport(tampered)


def test_support_root_must_include_declared_theorem():
    with pytest.raises(ValidationError, match="support root"):
        manifest(roots=["IndependentHelper"])
