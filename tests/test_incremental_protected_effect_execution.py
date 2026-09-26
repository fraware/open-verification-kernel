from __future__ import annotations

from copy import deepcopy
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
    ResourceRef,
    SemanticOrigin,
    SemanticPath,
)
from ovk.core.incremental_assurance import plan_incremental_assurance
from ovk.core.incremental_protected_effect_execution import (
    execute_incremental_protected_effect_assurance,
)
from ovk.core.models import VerificationSubject
from ovk.core.protected_effect_evaluation import (
    evaluate_protected_effect_integrity,
)
from ovk.core.protected_effect_evidence import (
    ProtectedEffectEvidenceCache,
    ProtectedEffectReusePolicy,
    ProtectedEffectRuntimeFingerprint,
    build_execution_fingerprint,
    protected_effect_evaluation_to_evidence,
)
from ovk.core.resource_identity import ResourceIdentityTerm
from ovk.core.result_cache import HardenedResultCache


TEST_KEY = b"incremental-protected-effect-test-key"


def _origin(path: str) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test.incremental",
        extractor_version="0.1.0",
    )


def _two_effect_ir(*, head_sha: str) -> AssuranceIR:
    return AssuranceIR(
        subject=VerificationSubject(
            repo="example/incremental",
            base_sha="base",
            head_sha=head_sha,
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.incremental",
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
                resource_id="r:invoice",
                symbol="invoice_id",
                identity_term=ResourceIdentityTerm.symbol("invoice_id"),
                origin=_origin("billing.py"),
            ),
            ResourceRef(
                resource_id="r:account",
                symbol="account_id",
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


def _runtime() -> ProtectedEffectRuntimeFingerprint:
    return ProtectedEffectRuntimeFingerprint(
        environment_digest="env:test",
        tool_digest="tool:test",
        worker_image_digest="sha256:worker-test",
        native_execution=True,
    )


def _provider(_effect_id: str) -> ProtectedEffectRuntimeFingerprint:
    return _runtime()


def _seed_cache(
    cache: ProtectedEffectEvidenceCache,
    ir: AssuranceIR,
    *,
    policy_digest: str = "policy-a",
) -> dict[str, str]:
    evaluations = evaluate_protected_effect_integrity(ir)
    digests: dict[str, str] = {}
    runtime = _runtime()

    for evaluation in evaluations:
        execution_fingerprint = build_execution_fingerprint(
            evaluation,
            environment_digest=runtime.environment_digest,
            tool_digest=runtime.tool_digest,
            worker_image_digest=runtime.worker_image_digest,
            native_execution=runtime.native_execution,
        )
        evidence = protected_effect_evaluation_to_evidence(
            ir,
            evaluation,
            policy_digest=policy_digest,
            execution_fingerprint=execution_fingerprint,
            signing_key=TEST_KEY,
        )
        cache.put(
            ir=ir,
            protected_effect_id=evaluation.protected_effect_id,
            policy_digest=policy_digest,
            execution_fingerprint=execution_fingerprint,
            evidence=evidence,
            signature_key=TEST_KEY,
        )
        assert evidence.evidence_digest is not None
        digests[evaluation.protected_effect_id] = evidence.evidence_digest

    return digests


def test_all_unchanged_effects_reuse_cache_without_running_evaluator(
    tmp_path: Path,
) -> None:
    base = _two_effect_ir(head_sha="head-a")
    head = _two_effect_ir(head_sha="head-b")
    cache = ProtectedEffectEvidenceCache(HardenedResultCache(tmp_path))
    prior = _seed_cache(cache, base)

    def must_not_run(*args, **kwargs):
        raise AssertionError("fresh evaluator must not run on complete cache reuse")

    result = execute_incremental_protected_effect_assurance(
        base,
        head,
        policy_digest="policy-a",
        runtime_fingerprint_provider=_provider,
        evidence_cache=cache,
        signature_key=TEST_KEY,
        signing_key=TEST_KEY,
        evaluator=must_not_run,
    )

    assert result.fresh_effects == []
    assert result.reused_effects == ["pe:delete", "pe:refund"]
    assert result.cache_miss_effects == []
    assert result.fresh_evaluations == []
    assert {item.subject["head_sha"] for item in result.evidence} == {"head-b"}
    assert all(item.signature is not None for item in result.evidence)
    for item in result.evidence:
        artifact = next(
            artifact
            for artifact in item.generated_artifacts
            if artifact.get("kind") == "protected_effect_evidence_reuse"
        )
        effect_id = item.intent["protected_effect_id"]
        assert artifact["prior_evidence_digest"] == prior[effect_id]


def test_one_semantic_change_runs_evaluator_only_for_changed_effect(
    tmp_path: Path,
) -> None:
    base = _two_effect_ir(head_sha="head-a")
    head = _two_effect_ir(head_sha="head-b")
    invoice = next(
        resource for resource in head.resources if resource.resource_id == "r:invoice"
    )
    invoice.identity_term = ResourceIdentityTerm.symbol("body.invoice_id")

    cache = ProtectedEffectEvidenceCache(HardenedResultCache(tmp_path))
    _seed_cache(cache, base)
    calls: list[list[str]] = []

    def counting_evaluator(ir, *, protected_effect_ids=None):
        requested = list(protected_effect_ids or [])
        calls.append(requested)
        return evaluate_protected_effect_integrity(
            ir,
            protected_effect_ids=requested,
        )

    result = execute_incremental_protected_effect_assurance(
        base,
        head,
        policy_digest="policy-a",
        runtime_fingerprint_provider=_provider,
        evidence_cache=cache,
        signature_key=TEST_KEY,
        signing_key=TEST_KEY,
        evaluator=counting_evaluator,
    )

    assert calls == [["pe:refund"]]
    assert result.fresh_effects == ["pe:refund"]
    assert result.reused_effects == ["pe:delete"]
    assert result.cache_miss_effects == []
    assert [item.protected_effect_id for item in result.fresh_evaluations] == [
        "pe:refund"
    ]
    assert len(result.evidence) == 2


def test_cache_miss_promotes_reuse_candidate_to_fresh_and_populates_cache(
    tmp_path: Path,
) -> None:
    base = _two_effect_ir(head_sha="head-a")
    head = _two_effect_ir(head_sha="head-b")
    cache = ProtectedEffectEvidenceCache(HardenedResultCache(tmp_path))
    calls: list[list[str]] = []

    def counting_evaluator(ir, *, protected_effect_ids=None):
        requested = list(protected_effect_ids or [])
        calls.append(requested)
        return evaluate_protected_effect_integrity(
            ir,
            protected_effect_ids=requested,
        )

    first = execute_incremental_protected_effect_assurance(
        base,
        head,
        policy_digest="policy-a",
        runtime_fingerprint_provider=_provider,
        evidence_cache=cache,
        signature_key=TEST_KEY,
        signing_key=TEST_KEY,
        evaluator=counting_evaluator,
    )

    assert calls == [["pe:delete", "pe:refund"]]
    assert first.fresh_effects == ["pe:delete", "pe:refund"]
    assert first.reused_effects == []
    assert first.cache_miss_effects == ["pe:delete", "pe:refund"]
    assert first.cache_store_failures == {}

    # A second transition with identical semantics must consume the entries just
    # installed by the first fresh run and execute no solver/checker work.
    next_head = _two_effect_ir(head_sha="head-c")

    def must_not_run(*args, **kwargs):
        raise AssertionError("fresh evaluator must not run after cache population")

    second = execute_incremental_protected_effect_assurance(
        head,
        next_head,
        policy_digest="policy-a",
        runtime_fingerprint_provider=_provider,
        evidence_cache=cache,
        signature_key=TEST_KEY,
        signing_key=TEST_KEY,
        evaluator=must_not_run,
    )
    assert second.fresh_effects == []
    assert second.reused_effects == ["pe:delete", "pe:refund"]


def test_policy_or_signature_mismatch_falls_back_to_fresh_verification(
    tmp_path: Path,
) -> None:
    base = _two_effect_ir(head_sha="head-a")
    head = _two_effect_ir(head_sha="head-b")
    cache = ProtectedEffectEvidenceCache(HardenedResultCache(tmp_path))
    _seed_cache(cache, base, policy_digest="policy-a")

    calls: list[list[str]] = []

    def counting_evaluator(ir, *, protected_effect_ids=None):
        requested = list(protected_effect_ids or [])
        calls.append(requested)
        return evaluate_protected_effect_integrity(
            ir,
            protected_effect_ids=requested,
        )

    wrong_policy = execute_incremental_protected_effect_assurance(
        base,
        head,
        policy_digest="policy-b",
        runtime_fingerprint_provider=_provider,
        evidence_cache=cache,
        signature_key=TEST_KEY,
        signing_key=TEST_KEY,
        evaluator=counting_evaluator,
    )
    assert wrong_policy.reused_effects == []
    assert wrong_policy.fresh_effects == ["pe:delete", "pe:refund"]

    calls.clear()
    wrong_signature = execute_incremental_protected_effect_assurance(
        base,
        head,
        policy_digest="policy-a",
        runtime_fingerprint_provider=_provider,
        evidence_cache=cache,
        signature_key=b"wrong-key",
        signing_key=TEST_KEY,
        evaluator=counting_evaluator,
    )
    assert calls == [["pe:delete", "pe:refund"]]
    assert wrong_signature.reused_effects == []
    assert wrong_signature.fresh_effects == ["pe:delete", "pe:refund"]


def test_revoked_cache_evidence_falls_back_to_fresh_verification(
    tmp_path: Path,
) -> None:
    base = _two_effect_ir(head_sha="head-a")
    head = _two_effect_ir(head_sha="head-b")
    cache = ProtectedEffectEvidenceCache(HardenedResultCache(tmp_path))
    prior = _seed_cache(cache, base)

    policy = ProtectedEffectReusePolicy(
        revoked_evidence_digests=sorted(prior.values()),
    )
    result = execute_incremental_protected_effect_assurance(
        base,
        head,
        policy_digest="policy-a",
        runtime_fingerprint_provider=_provider,
        evidence_cache=cache,
        reuse_policy=policy,
        signature_key=TEST_KEY,
        signing_key=TEST_KEY,
    )

    assert result.reused_effects == []
    assert result.fresh_effects == ["pe:delete", "pe:refund"]
    assert result.cache_miss_effects == ["pe:delete", "pe:refund"]


def test_missing_runtime_fingerprint_forces_fresh_and_skips_cache_store(
    tmp_path: Path,
) -> None:
    base = _two_effect_ir(head_sha="head-a")
    head = _two_effect_ir(head_sha="head-b")
    cache = ProtectedEffectEvidenceCache(HardenedResultCache(tmp_path))

    result = execute_incremental_protected_effect_assurance(
        base,
        head,
        policy_digest="policy-a",
        runtime_fingerprint_provider=lambda _effect_id: None,
        evidence_cache=cache,
        signing_key=TEST_KEY,
        reuse_policy=ProtectedEffectReusePolicy(require_signature=True),
    )

    assert result.reused_effects == []
    assert result.fresh_effects == ["pe:delete", "pe:refund"]
    assert result.cache_miss_reasons == {
        "pe:delete": "runtime_fingerprint_unavailable",
        "pe:refund": "runtime_fingerprint_unavailable",
    }
    assert result.cache_store_skipped == {
        "pe:delete": "runtime fingerprint unavailable",
        "pe:refund": "runtime fingerprint unavailable",
    }


def test_fresh_fail_or_unknown_is_emitted_but_never_cached(tmp_path: Path) -> None:
    base = _two_effect_ir(head_sha="head-a")
    head = _two_effect_ir(head_sha="head-b")

    # Removing a guard yields a concrete FAIL for this protected effect.
    head.guards = [guard for guard in head.guards if guard.guard_id != "g:refund"]
    refund_path = next(path for path in head.paths if path.path_id == "path:refund")
    refund_path.guard_ids = []

    cache = ProtectedEffectEvidenceCache(HardenedResultCache(tmp_path))
    result = execute_incremental_protected_effect_assurance(
        base,
        head,
        policy_digest="policy-a",
        runtime_fingerprint_provider=_provider,
        evidence_cache=cache,
        signature_key=TEST_KEY,
        signing_key=TEST_KEY,
    )

    evaluation = next(
        item for item in result.fresh_evaluations if item.protected_effect_id == "pe:refund"
    )
    assert evaluation.status == "fail"
    assert result.cache_store_skipped["pe:refund"] == "fresh evaluation is not PASS"


def test_evaluator_result_set_mismatch_fails_closed(tmp_path: Path) -> None:
    base = _two_effect_ir(head_sha="head-a")
    head = deepcopy(base)
    head.subject.head_sha = "head-b"

    def broken_evaluator(ir, *, protected_effect_ids=None):
        results = evaluate_protected_effect_integrity(
            ir,
            protected_effect_ids=list(protected_effect_ids or []),
        )
        return results[:1]

    with pytest.raises(ValueError, match="result set mismatch"):
        execute_incremental_protected_effect_assurance(
            base,
            head,
            policy_digest="policy-a",
            runtime_fingerprint_provider=_provider,
            evidence_cache=ProtectedEffectEvidenceCache(
                HardenedResultCache(tmp_path)
            ),
            signing_key=TEST_KEY,
            evaluator=broken_evaluator,
        )


def test_stale_precomputed_plan_is_rejected(tmp_path: Path) -> None:
    base = _two_effect_ir(head_sha="head-a")
    head = _two_effect_ir(head_sha="head-b")
    plan = plan_incremental_assurance(base, head)

    changed_head = deepcopy(head)
    changed_head.resources[0].identity_term = ResourceIdentityTerm.symbol(
        "changed.invoice_id"
    )

    with pytest.raises(ValueError, match="head digest does not match"):
        execute_incremental_protected_effect_assurance(
            base,
            changed_head,
            policy_digest="policy-a",
            runtime_fingerprint_provider=_provider,
            evidence_cache=ProtectedEffectEvidenceCache(
                HardenedResultCache(tmp_path)
            ),
            plan=plan,
            signing_key=TEST_KEY,
        )
