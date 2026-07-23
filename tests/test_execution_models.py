"""Serialization, digest determinism, and schema tests for execution models."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ovk.core.bundle import content_digest
from ovk.core.execution_models import (
    AbstractionCoverage,
    BackendCandidate,
    BackendObligation,
    BackendRejection,
    BackendSelection,
    ExecutionAttempt,
    ExecutionBudget,
    FallbackPolicy,
    MaterialReference,
    NormalizedBackendResult,
    ObligationExecutionRecord,
    RoutingDecision,
    VerificationObligation,
    attempt_digest_input,
    compute_abstraction_digest,
    compute_attempt_id,
    compute_backend_obligation_id,
    compute_obligation_id,
    compute_payload_digest,
    compute_routing_id,
    is_absolute_local_path,
    obligation_digest_input,
    validate_material_uri,
)
from ovk.core.models import (
    MergeRecommendation,
    RiskSeverity,
    SourceRange,
    VerificationStatus,
    VerificationSubject,
)
from ovk.core.schema_validation import load_json, validate_against_schema

SCHEMA_ROOT = Path("schemas")


def _subject() -> VerificationSubject:
    return VerificationSubject(repo="example/repo", head_sha="abc123", base_sha="def456", pull_request=7)


def _coverage() -> AbstractionCoverage:
    return AbstractionCoverage(
        status="complete",
        confidence=1.0,
        extracted_elements=2,
        expected_elements=2,
        source_ranges=[SourceRange(path="src/auth.py", start_line=1, end_line=10)],
    )


def _material(*, material_id: str = "mat-1", uri: str = "src/auth.py") -> MaterialReference:
    return MaterialReference(
        material_id=material_id,
        kind="source_file",
        uri=uri,
        sha256="a" * 64,
        size_bytes=128,
        source_revision="abc123",
        source_range=SourceRange(path=uri, start_line=1, end_line=4),
        trusted=True,
    )


def _budget() -> ExecutionBudget:
    return ExecutionBudget(
        total_wall_time_seconds=60.0,
        per_backend_wall_time_seconds=30.0,
        max_memory_mb=512,
        max_parallel_backends=2,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["z3", "deterministic"],
        denied_backends=["lean"],
    )


def _fallback() -> FallbackPolicy:
    return FallbackPolicy(allow_fallback=False, fallback_backends=[])


def _obligation(*, abstraction: dict[str, Any] | None = None) -> VerificationObligation:
    abs_payload = abstraction if abstraction is not None else {"kind": "access_control", "routes": ["/admin"]}
    materials = [_material(material_id="mat-b", uri="src/b.py"), _material(material_id="mat-a", uri="src/a.py")]
    provisional = VerificationObligation(
        obligation_id="pending",
        subject=_subject(),
        intent_id="no_admin_route_bypass",
        intent_version="0.1.0",
        lane="authorization",
        property_kind="access_control",
        severity=RiskSeverity.HIGH,
        compiler_id="authorization-compiler",
        compiler_version="0.1.0",
        materials=materials,
        abstraction=abs_payload,
        abstraction_digest=compute_abstraction_digest(abs_payload),
        coverage=_coverage(),
        acceptable_guarantees=["smt_satisfiability", "deterministic_evaluation"],
        required_capabilities=["smt", "json-constraints"],
        policy_digest=content_digest({"mode": "advisory"}),
    )
    return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})


def _routing(obligation_id: str) -> RoutingDecision:
    eligible = [
        BackendCandidate(
            backend="z3",
            score=0.9,
            support="supported",
            guarantee_type="smt_satisfiability",
            reasons=["domain match"],
            native_available=True,
        ),
        BackendCandidate(
            backend="deterministic",
            score=0.7,
            support="supported",
            guarantee_type="deterministic_evaluation",
            reasons=["always available"],
        ),
    ]
    selected = [
        BackendSelection(
            backend="z3",
            reason="highest score",
            expected_guarantee="smt_satisfiability",
            required=True,
            score=0.9,
        )
    ]
    rejected = [
        BackendRejection(backend="lean", reason="denied by budget", support="unsupported"),
    ]
    budget = _budget()
    fallback = _fallback()
    policy_digest = content_digest({"routing": {"mode": "shadow"}})
    routing_id = compute_routing_id(
        obligation_id=obligation_id,
        requested=["z3", "deterministic"],
        eligible=eligible,
        selected=selected,
        rejected=rejected,
        aggregation_policy="fail_dominant",
        fallback_policy=fallback,
        budget=budget,
        policy_digest=policy_digest,
        router_version="0.1.0",
    )
    return RoutingDecision(
        routing_id=routing_id,
        obligation_id=obligation_id,
        requested=["z3", "deterministic"],
        eligible=eligible,
        selected=selected,
        rejected=rejected,
        aggregation_policy="fail_dominant",
        fallback_policy=fallback,
        budget=budget,
        policy_digest=policy_digest,
    )


def _backend_obligation(obligation_id: str, routing_id: str) -> BackendObligation:
    payload = {"query": "unsat", "formula": "(assert false)"}
    provisional = BackendObligation(
        backend_obligation_id="pending",
        obligation_id=obligation_id,
        routing_id=routing_id,
        backend="z3",
        adapter_version="0.1.0",
        compiler_version="0.1.0",
        input_language="smtlib2",
        payload=payload,
        payload_digest=compute_payload_digest(payload),
        command_plan=["z3", "-T:30", "-"],
        expected_guarantee="smt_satisfiability",
    )
    return provisional.model_copy(update={"backend_obligation_id": compute_backend_obligation_id(provisional)})


def _attempt(backend_obligation_id: str) -> ExecutionAttempt:
    provisional = ExecutionAttempt(
        attempt_id="pending",
        backend_obligation_id=backend_obligation_id,
        backend="z3",
        required=True,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        duration_ms=1000.0,
        termination="completed",
        native_execution=True,
        tool_version="4.13.0",
        exit_code=0,
        stdout_digest=content_digest("unsat"),
        stderr_digest=content_digest(""),
        raw_result_digest=content_digest({"status": "unsat"}),
    )
    return provisional.model_copy(update={"attempt_id": compute_attempt_id(provisional)})


def _result(attempt_id: str) -> NormalizedBackendResult:
    return NormalizedBackendResult(
        attempt_id=attempt_id,
        backend="z3",
        status=VerificationStatus.PASS,
        guarantee_type="smt_satisfiability",
        assumptions=["finite abstraction"],
        limits=["timeout may yield unknown"],
        counterexamples=[],
        generated_artifacts=[],
    )


def _execution_record() -> ObligationExecutionRecord:
    obligation = _obligation()
    routing = _routing(obligation.obligation_id)
    backend_obl = _backend_obligation(obligation.obligation_id, routing.routing_id)
    attempt = _attempt(backend_obl.backend_obligation_id)
    return ObligationExecutionRecord(
        obligation=obligation,
        routing=routing,
        backend_obligations=[backend_obl],
        attempts=[attempt],
        results=[_result(attempt.attempt_id)],
        aggregate_status=VerificationStatus.PASS,
        merge_recommendation=MergeRecommendation.ALLOW,
        aggregation_reason="single required backend passed",
        open_obligations=[],
    )


# ---------------------------------------------------------------------------
# Round-trip serialization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "builder",
    [
        _obligation,
        lambda: _routing(_obligation().obligation_id),
        lambda: _backend_obligation("obl", "route"),
        lambda: _attempt("bo"),
        lambda: _result("att"),
        _execution_record,
        _coverage,
        _budget,
        _fallback,
        _material,
    ],
)
def test_model_json_round_trip(builder: Any) -> None:
    model = builder()
    payload = model.model_dump(mode="json")
    restored = type(model).model_validate(payload)
    assert restored.model_dump(mode="json") == payload


def test_obligation_execution_record_nested_round_trip() -> None:
    record = _execution_record()
    restored = ObligationExecutionRecord.model_validate(record.model_dump(mode="json"))
    assert restored.obligation.obligation_id == record.obligation.obligation_id
    assert restored.routing.routing_id == record.routing.routing_id
    assert restored.attempts[0].attempt_id == record.attempts[0].attempt_id


# ---------------------------------------------------------------------------
# Digest determinism and sensitivity
# ---------------------------------------------------------------------------


def test_obligation_id_is_deterministic() -> None:
    first = _obligation()
    second = _obligation()
    assert first.obligation_id == second.obligation_id
    assert compute_obligation_id(first) == first.obligation_id


def test_obligation_id_excludes_itself() -> None:
    obligation = _obligation()
    digest_input = obligation_digest_input(obligation)
    assert "obligation_id" not in digest_input
    mutated = obligation.model_copy(update={"obligation_id": "totally-different"})
    assert compute_obligation_id(mutated) == compute_obligation_id(obligation)


def test_obligation_id_changes_when_semantic_field_changes() -> None:
    base = _obligation()
    changed = _obligation(abstraction={"kind": "access_control", "routes": ["/admin", "/root"]})
    assert compute_obligation_id(base) != compute_obligation_id(changed)


def test_abstraction_and_payload_digests_are_deterministic() -> None:
    abstraction = {"a": 1, "b": [2, 3]}
    payload = {"query": "sat", "b": 2, "a": 1}
    assert compute_abstraction_digest(abstraction) == compute_abstraction_digest({"b": [2, 3], "a": 1})
    assert compute_payload_digest(payload) == compute_payload_digest({"a": 1, "b": 2, "query": "sat"})
    assert compute_abstraction_digest(abstraction) != compute_abstraction_digest({"a": 2})


def test_routing_id_is_deterministic_and_order_insensitive_for_sets() -> None:
    obligation = _obligation()
    kwargs = dict(
        obligation_id=obligation.obligation_id,
        requested=["deterministic", "z3"],
        eligible=[
            BackendCandidate(backend="z3", score=0.9, support="supported", guarantee_type="smt"),
            BackendCandidate(backend="deterministic", score=0.5, support="supported", guarantee_type="det"),
        ],
        selected=[
            BackendSelection(backend="z3", reason="score", expected_guarantee="smt", score=0.9),
        ],
        rejected=[
            BackendRejection(backend="lean", reason="denied"),
        ],
        aggregation_policy="fail_dominant",
        fallback_policy=_fallback(),
        budget=_budget(),
        policy_digest="policy",
        router_version="0.1.0",
    )
    left = compute_routing_id(**kwargs)
    reordered = dict(kwargs)
    reordered["requested"] = ["z3", "deterministic"]
    reordered["eligible"] = list(reversed(kwargs["eligible"]))
    right = compute_routing_id(**reordered)
    assert left == right


def test_routing_id_changes_when_budget_or_router_version_changes() -> None:
    obligation = _obligation()
    base_kwargs = dict(
        obligation_id=obligation.obligation_id,
        requested=["z3"],
        eligible=[BackendCandidate(backend="z3", score=1.0, support="supported", guarantee_type="smt")],
        selected=[BackendSelection(backend="z3", reason="only", expected_guarantee="smt")],
        rejected=[],
        aggregation_policy="fail_dominant",
        fallback_policy=_fallback(),
        budget=_budget(),
        policy_digest="policy",
        router_version="0.1.0",
    )
    base = compute_routing_id(**base_kwargs)
    other_budget = _budget().model_copy(update={"max_memory_mb": 256})
    assert compute_routing_id(**{**base_kwargs, "budget": other_budget}) != base
    assert compute_routing_id(**{**base_kwargs, "router_version": "0.2.0"}) != base


def test_attempt_id_excludes_wall_clock_timestamps() -> None:
    attempt = _attempt("bo-1")
    digest_input = attempt_digest_input(attempt)
    assert "attempt_id" not in digest_input
    assert "started_at" not in digest_input
    assert "finished_at" not in digest_input
    shifted = attempt.model_copy(
        update={"started_at": "2099-01-01T00:00:00Z", "finished_at": "2099-01-01T00:00:01Z"}
    )
    assert compute_attempt_id(shifted) == compute_attempt_id(attempt)


def test_attempt_id_changes_when_termination_changes() -> None:
    attempt = _attempt("bo-1")
    other = attempt.model_copy(update={"termination": "timeout", "exit_code": None})
    assert compute_attempt_id(attempt) != compute_attempt_id(other)


def test_materials_order_does_not_affect_obligation_id() -> None:
    obligation = _obligation()
    reversed_materials = list(reversed(obligation.materials))
    reordered = obligation.model_copy(update={"materials": reversed_materials})
    assert compute_obligation_id(reordered) == compute_obligation_id(obligation)


# ---------------------------------------------------------------------------
# Material URI validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "uri",
    [
        "src/auth.py",
        ".github/workflows/ci.yml",
        "repo:src/auth.py",
        "ovk-material:diff/pr-1",
        "https://example.com/plan.json",
        "git:refs/heads/main",
    ],
)
def test_material_uri_accepts_repo_relative_and_documented_schemes(uri: str) -> None:
    assert validate_material_uri(uri) == uri
    MaterialReference(
        material_id="m",
        kind="diff",
        uri=uri,
        sha256="b" * 64,
        size_bytes=1,
    )


@pytest.mark.parametrize(
    "uri",
    [
        "/etc/passwd",
        "C:\\Users\\secret\\file.txt",
        "C:/Users/secret/file.txt",
        "\\\\server\\share\\file",
        "file:///tmp/x",
        "file:/tmp/x",
    ],
)
def test_material_uri_rejects_absolute_local_paths(uri: str) -> None:
    assert is_absolute_local_path(uri) or uri.lower().startswith("file:")
    with pytest.raises(ValueError, match="absolute local path|drive letter|not allowed"):
        validate_material_uri(uri)
    with pytest.raises(ValidationError):
        MaterialReference(
            material_id="m",
            kind="source_file",
            uri=uri,
            sha256="c" * 64,
            size_bytes=1,
        )


def test_material_uri_rejects_unknown_schemes() -> None:
    with pytest.raises(ValueError, match="not allowed"):
        validate_material_uri("s3://bucket/key")


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def test_coverage_schema_accepts_model() -> None:
    report = validate_against_schema(
        _coverage().model_dump(mode="json"),
        load_json(SCHEMA_ROOT / "abstraction.coverage.schema.json"),
    )
    assert report.valid, report.issues


def test_obligation_schema_accepts_model() -> None:
    report = validate_against_schema(
        _obligation().model_dump(mode="json"),
        load_json(SCHEMA_ROOT / "verification.obligation.schema.json"),
    )
    assert report.valid, report.issues


def test_routing_schema_accepts_model() -> None:
    obligation = _obligation()
    report = validate_against_schema(
        _routing(obligation.obligation_id).model_dump(mode="json"),
        load_json(SCHEMA_ROOT / "backend.routing.schema.json"),
    )
    assert report.valid, report.issues


def test_execution_schema_accepts_all_artifact_shapes() -> None:
    schema = load_json(SCHEMA_ROOT / "backend.execution.schema.json")
    record = _execution_record()
    payloads = [
        record.backend_obligations[0].model_dump(mode="json"),
        record.attempts[0].model_dump(mode="json"),
        record.results[0].model_dump(mode="json"),
        record.model_dump(mode="json"),
    ]
    for payload in payloads:
        report = validate_against_schema(payload, schema)
        assert report.valid, report.issues


def test_obligation_schema_rejects_missing_required_field() -> None:
    payload = _obligation().model_dump(mode="json")
    del payload["policy_digest"]
    report = validate_against_schema(payload, load_json(SCHEMA_ROOT / "verification.obligation.schema.json"))
    assert not report.valid


def test_deep_copy_preserves_digests() -> None:
    record = _execution_record()
    cloned = ObligationExecutionRecord.model_validate(copy.deepcopy(record.model_dump(mode="json")))
    assert compute_obligation_id(cloned.obligation) == cloned.obligation.obligation_id
    assert cloned.routing.routing_id == record.routing.routing_id
