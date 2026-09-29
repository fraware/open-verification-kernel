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
from ovk.core.guarantee_assurance_state import (
    build_guarantee_assurance_snapshot,
)
from ovk.core.guarantee_graph import GuaranteeSelector, GuaranteeSpec
from ovk.core.guarantee_manifest import (
    GuaranteeManifest,
    GovernedGuaranteeContext,
    diff_guarantee_manifests,
)
from ovk.core.models import VerificationSubject
from ovk.core.pr_assurance_review import (
    build_pull_request_assurance_review,
    render_pull_request_assurance_review_markdown,
)
from ovk.core.protected_effect_evaluation import (
    evaluate_protected_effect_integrity,
)
from ovk.core.protected_effect_evidence import (
    ProtectedEffectRuntimeFingerprint,
    build_execution_fingerprint,
    protected_effect_evaluation_to_evidence,
)
from ovk.core.resource_identity import ResourceIdentityTerm


TEST_KEY = b"pr-assurance-review-test-key"


def _origin(path: str) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test.review",
        extractor_version="0.1.0",
    )


def _spec(*, effect_name: str = "billing.invoice.refund") -> GuaranteeSpec:
    return GuaranteeSpec(
        guarantee_id="G-REFUND",
        statement="Refund authorization for the acted invoice.",
        selector=GuaranteeSelector(
            effect_name=effect_name,
            resource_type="Invoice",
        ),
    )


def _ir(*, base_sha: str, head_sha: str, effect_name: str = "billing.invoice.refund") -> AssuranceIR:
    return AssuranceIR(
        subject=VerificationSubject(
            repo="example/review",
            base_sha=base_sha,
            head_sha=head_sha,
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.review",
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
                name=effect_name,
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


def _snapshot(*, base_sha: str, head_sha: str, spec: GuaranteeSpec):
    ir = _ir(
        base_sha=base_sha,
        head_sha=head_sha,
        effect_name=spec.selector.effect_name,
    )
    evaluation = evaluate_protected_effect_integrity(ir)[0]
    runtime = ProtectedEffectRuntimeFingerprint(
        environment_digest="env:test",
        tool_digest="tool:test",
        worker_image_digest="sha256:worker",
        native_execution=True,
    )
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
        [spec],
        [evidence],
        policy_digest="policy-a",
        signature_key=TEST_KEY,
    )


def _context(
    active: GuaranteeManifest,
    proposed: GuaranteeManifest | None = None,
) -> GovernedGuaranteeContext:
    head = proposed if proposed is not None else active
    diff = diff_guarantee_manifests(active, head)
    return GovernedGuaranteeContext(
        base_sha="a",
        active_source="base_revision",
        active_manifest=active,
        active_revision="a",
        assurance_target_available=True,
        proposed_manifest=head,
        proposal_valid=True,
        manifest_path_touched=diff.semantic_change,
        semantic_manifest_changed=diff.semantic_change,
        governance_review_required=diff.semantic_change,
        diff=diff,
    )


def test_review_joins_code_guarantee_and_assurance_diffs() -> None:
    manifest = GuaranteeManifest(guarantees=[_spec()])
    governance = _context(manifest)
    base_snapshot = _snapshot(base_sha="root", head_sha="a", spec=_spec())
    head_snapshot = _snapshot(base_sha="a", head_sha="b", spec=_spec())

    review = build_pull_request_assurance_review(
        repo="example/review",
        base_sha="a",
        head_sha="b",
        changed_files=["src/z.py", "src/a.py", "src/a.py"],
        governance=governance,
        base_snapshot=base_snapshot,
        head_snapshot=head_snapshot,
    )

    assert review.code_diff.changed_files == ["src/a.py", "src/z.py"]
    assert review.guarantee_diff.diff is not None
    assert review.guarantee_diff.diff.semantic_change is False
    assert review.assurance_diff.available is True
    assert review.assurance_diff.deltas[0].kind == "current_established_fresh"
    assert review.assurance_diff.freshly_established_guarantee_ids == [
        "G-REFUND"
    ]

    rendered = render_pull_request_assurance_review_markdown(review)
    assert "### Code Diff" in rendered
    assert "### Guarantee Diff" in rendered
    assert "### Assurance Diff" in rendered
    assert "current_established_fresh" in rendered


def test_proposed_guarantee_change_is_separate_from_active_assurance_target() -> None:
    active = GuaranteeManifest(guarantees=[_spec()])
    proposed = GuaranteeManifest(
        guarantees=[_spec(effect_name="billing.invoice.void")]
    )
    governance = _context(active, proposed)
    base_snapshot = _snapshot(base_sha="root", head_sha="a", spec=_spec())
    head_snapshot = _snapshot(base_sha="a", head_sha="b", spec=_spec())

    review = build_pull_request_assurance_review(
        repo="example/review",
        base_sha="a",
        head_sha="b",
        changed_files=[".verification/guarantees.json"],
        governance=governance,
        base_snapshot=base_snapshot,
        head_snapshot=head_snapshot,
    )

    assert review.guarantee_diff.governance_review_required is True
    assert review.guarantee_diff.diff is not None
    change = review.guarantee_diff.diff.modified_guarantees[0]
    assert change.machine_claim_changed is True
    assert review.assurance_diff.deltas[0].guarantee_id == "G-REFUND"
    assert review.assurance_diff.deltas[0].head_status == "established"


def test_review_rejects_head_snapshot_evaluated_under_proposed_definition() -> None:
    active_spec = _spec()
    proposed_spec = _spec(effect_name="billing.invoice.void")
    active = GuaranteeManifest(guarantees=[active_spec])
    proposed = GuaranteeManifest(guarantees=[proposed_spec])
    governance = _context(active, proposed)

    base_snapshot = _snapshot(
        base_sha="root",
        head_sha="a",
        spec=active_spec,
    )
    wrong_head_snapshot = _snapshot(
        base_sha="a",
        head_sha="b",
        spec=proposed_spec,
    )

    with pytest.raises(ValueError, match="trusted active base guarantee definitions"):
        build_pull_request_assurance_review(
            repo="example/review",
            base_sha="a",
            head_sha="b",
            changed_files=[".verification/guarantees.json"],
            governance=governance,
            base_snapshot=base_snapshot,
            head_snapshot=wrong_head_snapshot,
        )


def test_proposed_removal_does_not_remove_current_pr_assurance_target() -> None:
    active = GuaranteeManifest(guarantees=[_spec()])
    proposed = GuaranteeManifest()
    governance = _context(active, proposed)

    review = build_pull_request_assurance_review(
        repo="example/review",
        base_sha="a",
        head_sha="b",
        changed_files=[".verification/guarantees.json"],
        governance=governance,
        base_snapshot=_snapshot(
            base_sha="root",
            head_sha="a",
            spec=_spec(),
        ),
        head_snapshot=_snapshot(
            base_sha="a",
            head_sha="b",
            spec=_spec(),
        ),
    )

    assert review.guarantee_diff.diff is not None
    assert review.guarantee_diff.diff.removed_guarantee_ids == ["G-REFUND"]
    assert review.assurance_diff.deltas[0].guarantee_id == "G-REFUND"
    assert review.assurance_diff.deltas[0].head_status == "established"


def test_revision_mismatch_is_rejected() -> None:
    manifest = GuaranteeManifest(guarantees=[_spec()])
    governance = _context(manifest)

    with pytest.raises(ValueError, match="head snapshot base SHA"):
        build_pull_request_assurance_review(
            repo="example/review",
            base_sha="a",
            head_sha="b",
            changed_files=["src/app.py"],
            governance=governance,
            base_snapshot=_snapshot(
                base_sha="root",
                head_sha="a",
                spec=_spec(),
            ),
            head_snapshot=_snapshot(
                base_sha="other",
                head_sha="b",
                spec=_spec(),
            ),
        )


def test_missing_snapshots_leave_assurance_diff_explicitly_unavailable() -> None:
    manifest = GuaranteeManifest(guarantees=[_spec()])
    review = build_pull_request_assurance_review(
        repo="example/review",
        base_sha="a",
        head_sha="b",
        changed_files=["src/app.py"],
        governance=_context(manifest),
    )

    assert review.assurance_diff.available is False
    assert review.assurance_diff.reason_codes == [
        "base_snapshot_missing",
        "head_snapshot_missing",
    ]


def test_review_digest_is_stable_under_changed_file_order() -> None:
    manifest = GuaranteeManifest(guarantees=[_spec()])
    governance = _context(manifest)
    base_snapshot = _snapshot(base_sha="root", head_sha="a", spec=_spec())
    head_snapshot = _snapshot(base_sha="a", head_sha="b", spec=_spec())

    first = build_pull_request_assurance_review(
        repo="example/review",
        base_sha="a",
        head_sha="b",
        changed_files=["b.py", "a.py"],
        governance=governance,
        base_snapshot=base_snapshot,
        head_snapshot=head_snapshot,
    )
    second = build_pull_request_assurance_review(
        repo="example/review",
        base_sha="a",
        head_sha="b",
        changed_files=["a.py", "b.py", "a.py"],
        governance=governance,
        base_snapshot=deepcopy(base_snapshot),
        head_snapshot=deepcopy(head_snapshot),
    )

    assert first.review_digest == second.review_digest
    assert first.review_id == second.review_id
