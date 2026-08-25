"""Cache identity completeness and poisoning tests (WP-04)."""

from __future__ import annotations

import json
import time
from pathlib import Path

from ovk.core.authorization_compiler import compile_authorization_obligation
from ovk.core.execution_models import (
    BackendEnvironmentFingerprint,
    BackendObligation,
    CachedBackendExecution,
    ExecutionAttempt,
    NormalizedBackendResult,
    compute_backend_obligation_id,
    compute_payload_digest,
)
from ovk.core.models import VerificationStatus
from ovk.core.result_cache import (
    HardenedResultCache,
    build_backend_result_key_components,
    cache_key,
    digest_key_components,
)
from ovk.core.router import RoutingConfig, route_obligation
from ovk.adapters.authorization import build_authorization_registry
from ovk.core.execution_models import ExecutionBudget, ExecutionContext


def _obligation_and_routing():
    data = json.loads(Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8"))
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h", base_sha="b")
    registry = build_authorization_registry()
    budget = ExecutionBudget(
        total_wall_time_seconds=10,
        per_backend_wall_time_seconds=10,
        max_memory_mb=256,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["authorization-deterministic"],
    )
    routing = route_obligation(
        obligation,
        registry,
        context=ExecutionContext(subject=obligation.subject, budget=budget, policy_digest=obligation.policy_digest),
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1, accept_partial_primary=True),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    compiled = registry.get("authorization-deterministic").compile(obligation, routing)
    fingerprint = BackendEnvironmentFingerprint(
        backend=compiled.backend,
        adapter_version=compiled.adapter_version,
        environment_digest="env-1",
        tool_digest="tool-1",
        worker_image_digest="sha256:worker",
        native_available=True,
    )
    return obligation, routing, compiled, fingerprint


def _cached_execution(compiled: BackendObligation) -> CachedBackendExecution:
    attempt = ExecutionAttempt(
        attempt_id="attempt-test",
        backend_obligation_id=compiled.backend_obligation_id,
        backend=compiled.backend,
        required=True,
        started_at="2026-08-24T00:00:00Z",
        finished_at="2026-08-24T00:00:01Z",
        duration_ms=1.0,
        termination="completed",
        native_execution=True,
        tool_digest="tool-1",
        worker_image_digest="sha256:worker",
        raw_result_digest="a" * 64,
    )
    result = NormalizedBackendResult(
        attempt_id=attempt.attempt_id,
        backend=compiled.backend,
        status=VerificationStatus.PASS,
        guarantee_type=compiled.expected_guarantee,
    )
    return CachedBackendExecution(
        attempt=attempt,
        native_execution=True,
        tool_digest="tool-1",
        termination="completed",
        raw_result_digest="a" * 64,
        environment_fingerprint="env-1",
        normalized_result=result,
    )


def test_cache_identity_covers_subject_materials_route_and_tooling() -> None:
    obligation, routing, compiled, fingerprint = _obligation_and_routing()
    components = build_backend_result_key_components(
        obligation=obligation,
        routing=routing,
        backend_obligation=compiled,
        fingerprint=fingerprint,
    )
    required = {
        "subject",
        "obligation_id",
        "routing_id",
        "payload_digest",
        "policy_digest",
        "compiler_version",
        "adapter_version",
        "fallback_mode",
        "aggregation_policy",
        "tool_digest",
        "worker_image_digest",
    }
    assert required.issubset(components)
    assert components["payload_digest"] == compute_payload_digest(compiled.payload)
    assert compiled.backend_obligation_id == compute_backend_obligation_id(compiled)


def test_observational_timing_is_not_part_of_identity() -> None:
    first = cache_key("authorization", {"routes": []}, subject={"repo": "r", "head_sha": "h"})
    time.sleep(0.05)
    second = cache_key("authorization", {"routes": []}, subject={"repo": "r", "head_sha": "h"})
    assert first == second


def test_copying_record_to_another_key_is_rejected(tmp_path: Path) -> None:
    obligation, routing, compiled, fingerprint = _obligation_and_routing()
    cache = HardenedResultCache(tmp_path)
    components = build_backend_result_key_components(
        obligation=obligation, routing=routing, backend_obligation=compiled, fingerprint=fingerprint
    )
    cache.put_backend_result(components, _cached_execution(compiled))
    other_fingerprint = fingerprint.model_copy(update={"environment_digest": "env-2"})
    other = build_backend_result_key_components(
        obligation=obligation, routing=routing, backend_obligation=compiled, fingerprint=other_fingerprint
    )
    source_path = next((tmp_path / "backend-results").glob("*.json"))
    dest = tmp_path / "backend-results" / f"{digest_key_components(other)}.json"
    dest.write_text(source_path.read_text(encoding="utf-8"), encoding="utf-8")
    assert cache.get(other) is None


def test_edited_payload_is_rejected(tmp_path: Path) -> None:
    obligation, routing, compiled, fingerprint = _obligation_and_routing()
    cache = HardenedResultCache(tmp_path)
    components = build_backend_result_key_components(
        obligation=obligation, routing=routing, backend_obligation=compiled, fingerprint=fingerprint
    )
    cache.put_backend_result(components, _cached_execution(compiled))
    path = next((tmp_path / "backend-results").glob("*.json"))
    record = json.loads(path.read_text(encoding="utf-8"))
    record["payload"]["normalized_result"]["status"] = "fail"
    path.write_text(json.dumps(record), encoding="utf-8")
    assert cache.get(components) is None
    assert cache.get_cached_execution(components) is None


def test_swapped_backend_results_are_rejected(tmp_path: Path) -> None:
    obligation, routing, compiled, fingerprint = _obligation_and_routing()
    cache = HardenedResultCache(tmp_path)
    components = build_backend_result_key_components(
        obligation=obligation, routing=routing, backend_obligation=compiled, fingerprint=fingerprint
    )
    original = _cached_execution(compiled)
    swapped = original.model_copy(
        update={
            "normalized_result": original.normalized_result.model_copy(
                update={"backend": "forged-backend", "status": VerificationStatus.FAIL}
            )
        }
    )
    cache.put_backend_result(components, original)
    path = next((tmp_path / "backend-results").glob("*.json"))
    record = json.loads(path.read_text(encoding="utf-8"))
    record["payload"] = swapped.model_dump(mode="json")
    path.write_text(json.dumps(record), encoding="utf-8")
    hit = cache.get_cached_execution(components)
    assert hit is None


def test_cache_hit_reuses_original_attempt_isolation_and_tool_provenance(tmp_path: Path) -> None:
    obligation, routing, compiled, fingerprint = _obligation_and_routing()
    cache = HardenedResultCache(tmp_path)
    components = build_backend_result_key_components(
        obligation=obligation, routing=routing, backend_obligation=compiled, fingerprint=fingerprint
    )
    stored = _cached_execution(compiled)
    cache.put_backend_result(components, stored)
    hit = cache.get_cached_execution(components)
    assert hit is not None
    assert hit.attempt.attempt_id == stored.attempt.attempt_id
    assert hit.tool_digest == "tool-1"
    assert hit.attempt.worker_image_digest == "sha256:worker"
    assert hit.native_execution is True
