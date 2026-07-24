"""Adversarial and invariant coverage for wired control-plane modules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.adapters.authorization import build_authorization_registry
from ovk.core.attestation import bundle_to_statement
from ovk.core.authorization_compiler import compile_authorization_obligation
from ovk.core.backend_aggregation import aggregate_fail_dominant_v1, build_disagreement_artifact
from ovk.core.backend_control_plane import BackendControlPlane
from ovk.core.bundle import make_bundle
from ovk.core.counterexample_translator import write_generated_tests
from ovk.core.evidence_from_execution import execution_record_to_evidence
from ovk.core.evidence_invariants import check_evidence_bundle_invariants
from ovk.core.execution_models import (
    BackendSelection,
    ExecutionBudget,
    ExecutionContext,
    NormalizedBackendResult,
)
from ovk.core.models import (
    BackendClaim,
    MergeRecommendation,
    VerificationEvidence,
    VerificationStatus,
)
from ovk.core.render import render_evidence_markdown
from ovk.core.result_cache import ControlPlaneResultCache, HardenedResultCache
from ovk.core.router import RoutingConfig, route_obligation


def _budget(**kwargs) -> ExecutionBudget:
    base = dict(
        total_wall_time_seconds=60,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=2,
        allow_network=False,
        allow_repository_write=False,
    )
    base.update(kwargs)
    return ExecutionBudget(**base)


def test_unselected_backend_cannot_submit_evidence_affecting_decision() -> None:
    selected = [
        BackendSelection(
            backend="authorization-deterministic",
            reason="selected",
            expected_guarantee="deterministic_witness",
            required=True,
        )
    ]
    outcome = aggregate_fail_dominant_v1(
        obligation_id="obl",
        selected=selected,
        results=[
            NormalizedBackendResult(
                attempt_id="1",
                backend="authorization-deterministic",
                status=VerificationStatus.PASS,
                guarantee_type="deterministic_witness",
            ),
            NormalizedBackendResult(
                attempt_id="2",
                backend="rogue-unselected",
                status=VerificationStatus.FAIL,
                guarantee_type="policy_evaluation",
            ),
        ],
        acceptable_guarantees=["deterministic_witness"],
    )
    # Unselected fail must not flip a selected pass to block; quality error
    # forces human review instead of allowing the unexpected backend to decide.
    assert outcome.merge_recommendation == MergeRecommendation.REQUIRE_HUMAN_REVIEW
    assert outcome.status == VerificationStatus.UNKNOWN
    assert outcome.quality_error is True
    assert "unexpected=['rogue-unselected']" in outcome.reason
    assert outcome.merge_recommendation != MergeRecommendation.BLOCK


def test_selected_backend_omitted_from_execution_requires_review() -> None:
    selected = [
        BackendSelection(
            backend="authorization-deterministic",
            reason="selected",
            expected_guarantee="deterministic_witness",
            required=True,
        ),
        BackendSelection(
            backend="z3-native",
            reason="selected",
            expected_guarantee="smt_refutation_search",
            required=True,
        ),
    ]
    outcome = aggregate_fail_dominant_v1(
        obligation_id="obl",
        selected=selected,
        results=[
            NormalizedBackendResult(
                attempt_id="1",
                backend="authorization-deterministic",
                status=VerificationStatus.PASS,
                guarantee_type="deterministic_witness",
            ),
        ],
        acceptable_guarantees=["deterministic_witness", "smt_refutation_search"],
    )
    assert outcome.merge_recommendation == MergeRecommendation.REQUIRE_HUMAN_REVIEW
    assert outcome.quality_error is True


def test_forged_native_provenance_rejected() -> None:
    evidence = VerificationEvidence(
        evidence_id="ev-forged",
        schema_version="ovk.evidence.v2",
        subject={"repo": "r", "head_sha": "h"},
        intent={"intent_id": "no-admin-route-bypass", "title": "t"},
        backend_claims=[
            BackendClaim(
                backend="authorization-deterministic",
                guarantee_type="deterministic_witness",
                status=VerificationStatus.PASS,
            )
        ],
        decision={"merge_recommendation": "allow", "human_review_required": False},
        obligation_id="obl",
        routing_id="route",
        selected_backends=["authorization-deterministic"],
        executed_backends=["authorization-deterministic"],
        routing_enforced=True,
        generated_artifacts=[
            {
                "kind": "backend_provenance",
                "backend": "authorization-deterministic",
                "native_execution": True,  # forged: deterministic backend is not native
            }
        ],
    )
    bundle = make_bundle([evidence])
    issues = check_evidence_bundle_invariants(bundle)
    assert any("native" in issue.message.lower() for issue in issues)


def test_subject_and_routing_mismatched_cache_rejected(tmp_path: Path) -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    registry = build_authorization_registry()
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    budget = _budget(allowed_backends=["authorization-deterministic"])
    routing = route_obligation(
        obligation,
        registry,
        context=ExecutionContext(subject=obligation.subject, budget=budget, policy_digest="p1"),
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    cache = ControlPlaneResultCache(HardenedResultCache(tmp_path))
    plane = BackendControlPlane(cache=cache)
    plane.execute(obligation, routing, registry=registry)

    other = compile_authorization_obligation(data, repo="r", head_sha="other")
    other_routing = route_obligation(
        other,
        registry,
        context=ExecutionContext(subject=other.subject, budget=budget, policy_digest="p1"),
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    # Different subject => different cache key; must recompute, not return stale.
    assert other.obligation_id != obligation.obligation_id
    record = plane.execute(other, other_routing, registry=registry)
    assert record.obligation.subject.head_sha == "other"


def test_policy_digest_mismatch_separates_cache_entries(tmp_path: Path) -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8"))
    a = compile_authorization_obligation(data, repo="r", head_sha="h", policy_digest="dig-a")
    b = compile_authorization_obligation(data, repo="r", head_sha="h", policy_digest="dig-b")
    assert a.policy_digest != b.policy_digest
    assert a.obligation_id != b.obligation_id


def test_malformed_backend_output_maps_to_error_or_invalid() -> None:
    data = json.loads(Path("examples/auth_regression/input_malformed_missing_routes.json").read_text(encoding="utf-8"))
    registry = build_authorization_registry()
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    budget = _budget(allowed_backends=["authorization-deterministic"])
    routing = route_obligation(
        obligation,
        registry,
        context=ExecutionContext(subject=obligation.subject, budget=budget, policy_digest="p"),
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1, accept_partial_primary=True),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    record = BackendControlPlane(use_hardened_cache=False).execute(obligation, routing, registry=registry, cache=None)
    assert record.results
    assert record.results[0].status in {VerificationStatus.UNKNOWN, VerificationStatus.ERROR}
    assert record.attempts[0].termination in {"invalid_output", "completed", "tool_error"}


def test_incomplete_abstraction_cannot_allow_under_strict() -> None:
    head = (
        "from fastapi import Depends, FastAPI\n"
        "def require_admin():\n    return 'admin'\n"
        "app = FastAPI()\n"
        "@app.get('/admin', dependencies=[Depends(require_admin)])\n"
        "def admin():\n    return {}\n"
    )
    data = {"framework": "fastapi", "materials": {"path": "app.py", "head_source": head}}
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    assert obligation.coverage.status == "unknown"
    registry = build_authorization_registry()
    budget = _budget(allowed_backends=["authorization-deterministic"])
    routing = route_obligation(
        obligation,
        registry,
        context=ExecutionContext(subject=obligation.subject, budget=budget, policy_digest="p"),
        config=RoutingConfig(
            prefer_deterministic=True,
            max_selected_backends=1,
            accept_partial_primary=True,
        ),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    record = BackendControlPlane(use_hardened_cache=False).execute(obligation, routing, registry=registry, cache=None)
    evidence = execution_record_to_evidence(record, routing_enforced=True)
    assert evidence.decision["merge_recommendation"] != "allow"


def test_backend_timeout_never_deterministic_pass_fallback() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8"))
    registry = build_authorization_registry()
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    budget = _budget(
        total_wall_time_seconds=0,
        per_backend_wall_time_seconds=0,
        allowed_backends=["authorization-deterministic"],
    )
    routing = route_obligation(
        obligation,
        registry,
        context=ExecutionContext(subject=obligation.subject, budget=budget, policy_digest="p"),
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1, accept_partial_primary=True),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    if not routing.selected:
        routing = routing.model_copy(
            update={
                "selected": [
                    BackendSelection(
                        backend="authorization-deterministic",
                        reason="forced-timeout-test",
                        expected_guarantee="deterministic_witness",
                        required=True,
                        score=1.0,
                    )
                ]
            }
        )
    record = BackendControlPlane(use_hardened_cache=False).execute(obligation, routing, registry=registry, cache=None)
    assert record.aggregate_status != VerificationStatus.PASS
    assert record.merge_recommendation != MergeRecommendation.ALLOW
    assert record.attempts[0].termination == "timeout"
    assert record.results[0].status == VerificationStatus.UNKNOWN


def test_disagreement_artifact_is_explicit() -> None:
    artifact = build_disagreement_artifact(
        obligation_id="obl",
        results=[
            NormalizedBackendResult(
                attempt_id="1",
                backend="a",
                status=VerificationStatus.PASS,
                guarantee_type="g",
            ),
            NormalizedBackendResult(
                attempt_id="2",
                backend="b",
                status=VerificationStatus.FAIL,
                guarantee_type="g",
            ),
        ],
        resolution="fail_dominant",
    )
    assert artifact["kind"] == "backend_disagreement"
    assert artifact["obligation_id"] == "obl"
    assert len(artifact["results"]) == 2


def test_render_and_attestation_expose_enforced_fields() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    registry = build_authorization_registry()
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    budget = _budget(allowed_backends=["authorization-deterministic"])
    routing = route_obligation(
        obligation,
        registry,
        context=ExecutionContext(subject=obligation.subject, budget=budget, policy_digest="p"),
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    record = BackendControlPlane(use_hardened_cache=False).execute(obligation, routing, registry=registry, cache=None)
    evidence = execution_record_to_evidence(record, routing_enforced=True, schema_version="ovk.evidence.v2")
    markdown = render_evidence_markdown(evidence)
    assert "Compiler:" in markdown
    assert "Coverage:" in markdown
    assert "Selected:" in markdown
    assert "Executed:" in markdown
    assert "Outcome class:" in markdown
    assert "property_failure" in markdown or "Recommendation:" in markdown

    bundle = make_bundle([evidence])
    statement = bundle_to_statement(bundle)
    item = statement["predicate"]["verification"]["evidence"][0]
    assert item["compiler"]
    assert item["coverage"]
    assert item["materials"] is not None
    assert item["selected_backends"]
    assert item["executed_backends"]


def test_generated_regression_tests_path_constrained(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    evidence = VerificationEvidence(
        evidence_id="ev",
        subject={"repo": "r", "head_sha": "h"},
        intent={"intent_id": "no-admin-route-bypass"},
        backend_claims=[
            BackendClaim(
                backend="authorization-deterministic",
                guarantee_type="deterministic_witness",
                status=VerificationStatus.FAIL,
            )
        ],
        counterexamples=[
            {
                "summary": "bypass",
                "failure_mode": "admin_route_bypass",
                "route": "/admin",
                "user_role": "user",
            }
        ],
        decision={"merge_recommendation": "block"},
    )
    bundle = make_bundle([evidence])
    out = tmp_path / ".verification" / "generated_tests"
    written = write_generated_tests(bundle, out)
    assert written
    assert all(path.resolve().is_relative_to(tmp_path.resolve()) for path in written)
    py_files = [path for path in written if path.suffix == ".py"]
    assert py_files
    assert "not auto-executed" in py_files[0].read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="auto-execution"):
        write_generated_tests(bundle, out, allow_auto_exec=True)

    # Use an absolute path under the filesystem root so Linux CI and Windows
    # both treat it as outside cwd/temp/.verification (Windows drive-letter
    # strings are not absolute on Linux).
    import tempfile as _tempfile

    outside = Path(Path(_tempfile.gettempdir()).resolve().anchor) / "ovk-escape-forbidden-tests"
    with pytest.raises(ValueError, match="path traversal|outside workspace or temp"):
        write_generated_tests(bundle, outside)
