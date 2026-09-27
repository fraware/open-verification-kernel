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
from ovk.core.guarantee_assurance_ledger import (
    build_guarantee_assurance_ledger_entry,
    compute_guarantee_assurance_snapshot_digest,
    validate_guarantee_assurance_snapshot_structure,
    verify_guarantee_assurance_ledger_chain,
    verify_guarantee_assurance_ledger_entry,
)
from ovk.core.guarantee_assurance_state import (
    build_guarantee_assurance_snapshot,
)
from ovk.core.guarantee_graph import GuaranteeSelector, GuaranteeSpec
from ovk.core.models import VerificationSubject
from ovk.core.protected_effect_evaluation import (
    evaluate_protected_effect_integrity,
)
from ovk.core.protected_effect_evidence import (
    ProtectedEffectRuntimeFingerprint,
    build_execution_fingerprint,
    protected_effect_evaluation_to_evidence,
)
from ovk.core.resource_identity import ResourceIdentityTerm


TEST_KEY = b"guarantee-ledger-test-key"


def _origin(path: str) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test.ledger",
        extractor_version="0.1.0",
    )


def _ir(*, base_sha: str, head_sha: str) -> AssuranceIR:
    return AssuranceIR(
        subject=VerificationSubject(
            repo="example/ledger",
            base_sha=base_sha,
            head_sha=head_sha,
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.ledger",
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
            )
        ],
        effects=[
            EffectRef(
                effect_id="e:refund",
                name="billing.invoice.refund",
                origin=_origin("billing.py"),
            )
        ],
        guards=[
            AuthorizationGuard(
                guard_id="g:refund",
                principal_id="p:user",
                effect_id="e:refund",
                resource_id="r:invoice",
                origin=_origin("billing.py"),
            )
        ],
        protected_effects=[
            ProtectedEffect(
                protected_effect_id="pe:refund",
                principal_id="p:user",
                effect_id="e:refund",
                resource_id="r:invoice",
                origin=_origin("billing.py"),
            )
        ],
        paths=[
            SemanticPath(
                path_id="path:refund",
                entrypoint="POST /refund",
                guard_ids=["g:refund"],
                protected_effect_ids=["pe:refund"],
                origin=_origin("billing.py"),
            )
        ],
    )


def _spec() -> GuaranteeSpec:
    return GuaranteeSpec(
        guarantee_id="G-REFUND",
        statement="Refund authorization for the acted invoice.",
        selector=GuaranteeSelector(
            effect_name="billing.invoice.refund",
            resource_type="Invoice",
        ),
    )


def _runtime() -> ProtectedEffectRuntimeFingerprint:
    return ProtectedEffectRuntimeFingerprint(
        environment_digest="env:test",
        tool_digest="tool:test",
        worker_image_digest="sha256:worker",
        native_execution=True,
    )


def _snapshot(*, base_sha: str, head_sha: str):
    ir = _ir(base_sha=base_sha, head_sha=head_sha)
    evaluation = evaluate_protected_effect_integrity(ir)[0]
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
    return build_guarantee_assurance_snapshot(
        ir,
        [_spec()],
        [evidence],
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )


def test_genesis_entry_is_content_addressed_signed_and_self_valid() -> None:
    snapshot = _snapshot(base_sha="root", head_sha="a")
    entry = build_guarantee_assurance_ledger_entry(
        snapshot,
        signing_key=TEST_KEY,
        created_at="2026-09-27T00:00:00Z",
    )

    assert entry.sequence == 0
    assert entry.previous_entry_digest is None
    assert entry.previous_snapshot_digest is None
    assert entry.snapshot_digest == compute_guarantee_assurance_snapshot_digest(
        snapshot
    )
    assert entry.signature["algorithm"] == "hmac-sha256"
    assert entry.deltas[0].kind == "new_guarantee"
    assert verify_guarantee_assurance_ledger_entry(
        entry,
        key=TEST_KEY,
    ).valid


def test_second_entry_binds_exact_predecessor_and_revision_continuity() -> None:
    first = build_guarantee_assurance_ledger_entry(
        _snapshot(base_sha="root", head_sha="a"),
        signing_key=TEST_KEY,
        created_at="2026-09-27T00:00:00Z",
    )
    second = build_guarantee_assurance_ledger_entry(
        _snapshot(base_sha="a", head_sha="b"),
        signing_key=TEST_KEY,
        previous=first,
        created_at="2026-09-27T00:01:00Z",
    )

    assert second.sequence == 1
    assert second.previous_entry_digest == first.entry_digest
    assert second.previous_snapshot_digest == first.snapshot_digest
    assert second.deltas[0].kind == "current_established_fresh"

    result = verify_guarantee_assurance_ledger_entry(
        second,
        key=TEST_KEY,
        previous=first,
    )
    assert result.valid, result.reason_codes

    chain = verify_guarantee_assurance_ledger_chain(
        [first, second],
        key=TEST_KEY,
    )
    assert chain.valid, chain.reason_codes


def test_builder_rejects_revision_discontinuity() -> None:
    first = build_guarantee_assurance_ledger_entry(
        _snapshot(base_sha="root", head_sha="a"),
        signing_key=TEST_KEY,
    )

    with pytest.raises(ValueError, match="revision discontinuity"):
        build_guarantee_assurance_ledger_entry(
            _snapshot(base_sha="other", head_sha="b"),
            signing_key=TEST_KEY,
            previous=first,
        )


def test_tampered_snapshot_breaks_snapshot_entry_and_signature_binding() -> None:
    entry = build_guarantee_assurance_ledger_entry(
        _snapshot(base_sha="root", head_sha="a"),
        signing_key=TEST_KEY,
    )
    tampered_snapshot = entry.snapshot.model_copy(
        update={"policy_digest": "attacker-policy"}
    )
    tampered = entry.model_copy(update={"snapshot": tampered_snapshot})

    result = verify_guarantee_assurance_ledger_entry(
        tampered,
        key=TEST_KEY,
    )
    assert result.valid is False
    assert "snapshot_digest_mismatch" in result.reason_codes
    assert "entry_digest_mismatch" in result.reason_codes
    assert "invalid_entry_signature" in result.reason_codes


def test_wrong_signature_key_is_rejected() -> None:
    entry = build_guarantee_assurance_ledger_entry(
        _snapshot(base_sha="root", head_sha="a"),
        signing_key=TEST_KEY,
    )
    result = verify_guarantee_assurance_ledger_entry(
        entry,
        key=b"wrong-key",
    )
    assert result.valid is False
    assert "invalid_entry_signature" in result.reason_codes


def test_non_genesis_entry_requires_predecessor_for_verification() -> None:
    first = build_guarantee_assurance_ledger_entry(
        _snapshot(base_sha="root", head_sha="a"),
        signing_key=TEST_KEY,
    )
    second = build_guarantee_assurance_ledger_entry(
        _snapshot(base_sha="a", head_sha="b"),
        signing_key=TEST_KEY,
        previous=first,
    )

    result = verify_guarantee_assurance_ledger_entry(
        second,
        key=TEST_KEY,
    )
    assert result.valid is False
    assert "predecessor_required" in result.reason_codes


def test_tampered_predecessor_link_is_rejected() -> None:
    first = build_guarantee_assurance_ledger_entry(
        _snapshot(base_sha="root", head_sha="a"),
        signing_key=TEST_KEY,
    )
    second = build_guarantee_assurance_ledger_entry(
        _snapshot(base_sha="a", head_sha="b"),
        signing_key=TEST_KEY,
        previous=first,
    )
    tampered = second.model_copy(
        update={"previous_entry_digest": "0" * 64}
    )

    result = verify_guarantee_assurance_ledger_entry(
        tampered,
        key=TEST_KEY,
        previous=first,
    )
    assert result.valid is False
    assert "previous_entry_digest_mismatch" in result.reason_codes
    assert "entry_digest_mismatch" in result.reason_codes


def test_snapshot_structure_rejects_fabricated_established_state() -> None:
    snapshot = _snapshot(base_sha="root", head_sha="a")
    state = snapshot.states[0]
    fabricated = state.model_copy(
        update={
            "evidence_digest": None,
            "evidence_origin": None,
            "protected_effect_claim_status": "unknown",
        }
    )
    invalid_snapshot = snapshot.model_copy(update={"states": [fabricated]})

    issues = validate_guarantee_assurance_snapshot_structure(invalid_snapshot)
    assert "established_missing_evidence_digest:G-REFUND" in issues
    assert "established_missing_evidence_origin:G-REFUND" in issues
    assert "established_without_pass_claim:G-REFUND" in issues

    with pytest.raises(ValueError, match="invalid guarantee assurance snapshot"):
        build_guarantee_assurance_ledger_entry(
            invalid_snapshot,
            signing_key=TEST_KEY,
        )


def test_chain_detects_tampered_middle_entry() -> None:
    first = build_guarantee_assurance_ledger_entry(
        _snapshot(base_sha="root", head_sha="a"),
        signing_key=TEST_KEY,
    )
    second = build_guarantee_assurance_ledger_entry(
        _snapshot(base_sha="a", head_sha="b"),
        signing_key=TEST_KEY,
        previous=first,
    )
    third = build_guarantee_assurance_ledger_entry(
        _snapshot(base_sha="b", head_sha="c"),
        signing_key=TEST_KEY,
        previous=second,
    )

    altered = deepcopy(second)
    altered.entry_digest = "f" * 64

    result = verify_guarantee_assurance_ledger_chain(
        [first, altered, third],
        key=TEST_KEY,
    )
    assert result.valid is False
    assert any("entry[1]:entry_digest_mismatch" == reason for reason in result.reason_codes)
    assert any(
        "entry[2]:previous_entry_digest_mismatch" == reason
        for reason in result.reason_codes
    )
