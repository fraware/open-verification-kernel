"""Hardened verification cache tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from ovk import __version__ as OVK_VERSION
from ovk.core.execution_models import (
    AbstractionCoverage,
    BackendEnvironmentFingerprint,
    BackendObligation,
    BackendSelection,
    ExecutionBudget,
    FallbackPolicy,
    NormalizedBackendResult,
    RoutingDecision,
    VerificationObligation,
    compute_abstraction_digest,
    compute_obligation_id,
    compute_payload_digest,
)
from ovk.core.models import RiskSeverity, VerificationStatus, VerificationSubject
from ovk.core.result_cache import (
    CACHE_SCHEMA_VERSION,
    NAMESPACE_BACKEND_RESULTS,
    HardenedResultCache,
    build_aggregate_key_components,
    build_backend_result_key_components,
    digest_key_components,
)


def _budget() -> ExecutionBudget:
    return ExecutionBudget(
        total_wall_time_seconds=60,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
    )


def _obligation(*, repo: str = "acme/api", head_sha: str = "abc", base_sha: str | None = "def") -> VerificationObligation:
    abstraction = {"kind": "test", "input": {"x": 1}}
    provisional = VerificationObligation(
        obligation_id="pending",
        subject=VerificationSubject(repo=repo, head_sha=head_sha, base_sha=base_sha),
        intent_id="test-intent",
        intent_version="0.1.0",
        lane="infrastructure",
        property_kind="safety",
        severity=RiskSeverity.HIGH,
        compiler_id="ovk.test.v1",
        compiler_version="0.1.0",
        materials=[],
        abstraction=abstraction,
        abstraction_digest=compute_abstraction_digest(abstraction),
        coverage=AbstractionCoverage(status="complete", confidence=1.0, extracted_elements=1),
        acceptable_guarantees=["exposure_graph_check"],
        required_capabilities=["infrastructure"],
        policy_digest="policy-1",
    )
    return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})


def _routing(obligation: VerificationObligation, *, routing_id: str = "routing-1") -> RoutingDecision:
    selected = [
        BackendSelection(
            backend="infrastructure-deterministic",
            reason="test",
            expected_guarantee="exposure_graph_check",
            required=True,
            score=1.0,
        ),
    ]
    return RoutingDecision(
        routing_id=routing_id,
        obligation_id=obligation.obligation_id,
        requested=["infrastructure-deterministic"],
        eligible=[],
        selected=selected,
        rejected=[],
        aggregation_policy="fail_dominant_v1",
        fallback_policy=FallbackPolicy(allow_fallback=False),
        budget=_budget(),
        policy_digest=obligation.policy_digest,
    )


def _backend_obligation(obligation: VerificationObligation, routing: RoutingDecision) -> BackendObligation:
    payload = {"input": {"x": 1}}
    return BackendObligation(
        backend_obligation_id="bo-1",
        obligation_id=obligation.obligation_id,
        routing_id=routing.routing_id,
        backend="infrastructure-deterministic",
        adapter_version="0.1.0",
        compiler_version="0.1.0",
        input_language="json",
        payload=payload,
        payload_digest=compute_payload_digest(payload),
        command_plan=["test"],
        environment_requirements={},
        expected_guarantee="exposure_graph_check",
    )


def _fingerprint() -> BackendEnvironmentFingerprint:
    return BackendEnvironmentFingerprint(
        backend="infrastructure-deterministic",
        adapter_version="0.1.0",
        environment_digest="env-1",
        tool_version="0.1.0",
        native_available=False,
    )


def test_key_components_include_required_fields() -> None:
    obligation = _obligation()
    routing = _routing(obligation)
    backend_obligation = _backend_obligation(obligation, routing)
    components = build_backend_result_key_components(
        obligation=obligation,
        routing=routing,
        backend_obligation=backend_obligation,
        fingerprint=_fingerprint(),
    )
    required = {
        "cache_schema_version",
        "ovk_version",
        "subject",
        "obligation_id",
        "routing_id",
        "backend_obligation_id",
        "environment_digest",
        "policy_digest",
        "compiler_version",
        "adapter_version",
        "input_format",
        "fallback_mode",
        "aggregation_policy",
    }
    assert required.issubset(components)
    assert components["cache_schema_version"] == CACHE_SCHEMA_VERSION
    assert components["ovk_version"] == OVK_VERSION
    assert components["namespace"] == NAMESPACE_BACKEND_RESULTS


def test_subject_mismatch_is_cache_miss(tmp_path: Path) -> None:
    cache = HardenedResultCache(tmp_path)
    obligation = _obligation(repo="acme/api")
    routing = _routing(obligation)
    backend_obligation = _backend_obligation(obligation, routing)
    components = build_backend_result_key_components(
        obligation=obligation,
        routing=routing,
        backend_obligation=backend_obligation,
        fingerprint=_fingerprint(),
    )
    result = NormalizedBackendResult(
        attempt_id="a1",
        backend="infrastructure-deterministic",
        status=VerificationStatus.PASS,
        guarantee_type="exposure_graph_check",
    )
    cache.put_backend_result(components, result)

    other = _obligation(repo="other/repo")
    other_components = build_backend_result_key_components(
        obligation=other,
        routing=_routing(other),
        backend_obligation=_backend_obligation(other, _routing(other)),
        fingerprint=_fingerprint(),
    )
    # Force same digest filename by writing under requested path then reading with
    # mismatched subject components against a forged file — validate components win.
    forged = dict(components)
    forged["subject"] = {"repo": "other/repo", "head_sha": "abc", "base_sha": "def"}
    # Different digest => miss via filename.
    assert cache.get_backend_result(forged) is None
    # Same digest filename with mutated stored subject must not hit.
    key = digest_key_components(components)
    path = cache.namespace_dir(NAMESPACE_BACKEND_RESULTS) / f"{key}.json"
    import json

    record = json.loads(path.read_text(encoding="utf-8"))
    record["key_components"]["subject"] = {"repo": "evil/repo", "head_sha": "abc", "base_sha": "def"}
    # Keep key_digest matching filename so only component validation catches it.
    path.write_text(json.dumps(record), encoding="utf-8")
    assert cache.get_backend_result(components) is None
    assert other_components["subject"]["repo"] == "other/repo"


def test_routing_mismatch_is_cache_miss(tmp_path: Path) -> None:
    cache = HardenedResultCache(tmp_path)
    obligation = _obligation()
    routing = _routing(obligation)
    backend_obligation = _backend_obligation(obligation, routing)
    components = build_backend_result_key_components(
        obligation=obligation,
        routing=routing,
        backend_obligation=backend_obligation,
        fingerprint=_fingerprint(),
    )
    cache.put_backend_result(
        components,
        NormalizedBackendResult(
            attempt_id="a1",
            backend="infrastructure-deterministic",
            status=VerificationStatus.PASS,
            guarantee_type="exposure_graph_check",
        ),
    )
    mismatched = dict(components)
    mismatched["routing_id"] = "forged-routing"
    assert cache.get_backend_result(mismatched) is None


def test_namespaces_are_separated(tmp_path: Path) -> None:
    cache = HardenedResultCache(tmp_path)
    assert (tmp_path / "compiled").exists() is False
    cache.namespace_dir("compiled")
    cache.namespace_dir("backend-results")
    cache.namespace_dir("aggregate")
    assert (tmp_path / "compiled").is_dir()
    assert (tmp_path / "backend-results").is_dir()
    assert (tmp_path / "aggregate").is_dir()


def test_aggregate_not_cached_before_attempts_validated(tmp_path: Path) -> None:
    cache = HardenedResultCache(tmp_path)
    obligation = _obligation()
    routing = _routing(obligation)
    assert (
        cache.put_aggregate(
            obligation=obligation,
            routing=routing,
            attempt_digests=[],
            aggregate_payload={"status": "pass"},
            attempts_validated=False,
        )
        is None
    )
    assert (
        cache.put_aggregate(
            obligation=obligation,
            routing=routing,
            attempt_digests=["only-one"],  # selected has 1, but empty digest rejected below
            aggregate_payload={"status": "pass"},
            attempts_validated=True,
        )
        is not None
    )
    # Empty digest in attempts must be rejected.
    assert (
        cache.put_aggregate(
            obligation=obligation,
            routing=routing,
            attempt_digests=[""],
            aggregate_payload={"status": "pass"},
            attempts_validated=True,
        )
        is None
    )


def test_aggregate_key_includes_aggregation_policy() -> None:
    obligation = _obligation()
    routing = _routing(obligation)
    components = build_aggregate_key_components(
        obligation=obligation,
        routing=routing,
        attempt_digests=["a", "b"],
    )
    assert components["aggregation_policy"] == "fail_dominant_v1"
    assert components["namespace"] == "aggregate"
    assert components["attempt_digests"] == ["a", "b"]


def test_round_trip_backend_result(tmp_path: Path) -> None:
    cache = HardenedResultCache(tmp_path)
    obligation = _obligation()
    routing = _routing(obligation)
    backend_obligation = _backend_obligation(obligation, routing)
    components = build_backend_result_key_components(
        obligation=obligation,
        routing=routing,
        backend_obligation=backend_obligation,
        fingerprint=_fingerprint(),
    )
    result = NormalizedBackendResult(
        attempt_id="a1",
        backend="infrastructure-deterministic",
        status=VerificationStatus.FAIL,
        guarantee_type="exposure_graph_check",
        counterexamples=[{"summary": "exposed"}],
    )
    cache.put_backend_result(components, result)
    loaded = cache.get_backend_result(components)
    assert loaded is not None
    assert loaded.status == VerificationStatus.FAIL
    assert loaded.counterexamples == [{"summary": "exposed"}]


def test_unknown_namespace_rejected(tmp_path: Path) -> None:
    cache = HardenedResultCache(tmp_path)
    with pytest.raises(ValueError, match="unknown cache namespace"):
        cache.namespace_dir("evil")
