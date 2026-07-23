"""Backend control plane for compiling, executing, and aggregating obligations.

In shadow mode the control plane runs beside legacy lane evaluation; legacy
results remain authoritative until a lane opts into enforced routing.

By default the control plane uses ``ControlPlaneResultCache`` (hardened
namespaces + key-component validation) for backend results. Pass
``cache=None`` explicitly to ``execute`` only when caching must be disabled.
Adapters describe computation; ``LocalSubprocessWorker`` (or any
``BackendWorker``) is available for native/subprocess backends.
"""

from __future__ import annotations

import inspect
import time
from datetime import datetime, timezone
from typing import Any, Protocol

from ovk.core.backend_aggregation import aggregate_results
from ovk.core.backend_registry import BackendRegistry, BackendRegistryError
from ovk.core.bundle import content_digest
from ovk.core.execution_budget import BackendWorker, LocalSubprocessWorker
from ovk.core.execution_models import (
    BackendEnvironmentFingerprint,
    BackendObligation,
    ExecutionAttempt,
    ExecutionBudget,
    NormalizedBackendResult,
    ObligationExecutionRecord,
    RawBackendExecution,
    RoutingDecision,
    VerificationObligation,
    compute_attempt_id,
    compute_raw_execution_digests,
)
from ovk.core.models import MergeRecommendation, VerificationStatus
from ovk.core.result_cache import ControlPlaneResultCache


class ResultCache(Protocol):
    """Minimal cache protocol used by the control plane."""

    def get(self, key: str) -> NormalizedBackendResult | None: ...

    def put(self, key: str, value: NormalizedBackendResult, *, meta: dict[str, Any]) -> None: ...


_CACHE_UNSET = object()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def control_plane_cache_key(
    *,
    obligation: VerificationObligation,
    routing: RoutingDecision,
    backend_obligation: BackendObligation,
    fingerprint: BackendEnvironmentFingerprint,
    input_format: str = "json",
) -> str:
    """Build a cache key incorporating control-plane identity components.

    Key material includes cache schema version, OVK version, subject,
    obligation/routing/backend-obligation IDs, environment fingerprint,
    policy digest, compiler/adapter versions, input format, fallback mode,
    and aggregation policy.
    """
    from ovk.core.result_cache import (
        build_backend_result_key_components,
        digest_key_components,
    )

    return digest_key_components(
        build_backend_result_key_components(
            obligation=obligation,
            routing=routing,
            backend_obligation=backend_obligation,
            fingerprint=fingerprint,
            input_format=input_format,
        )
    )


def control_plane_cache_components(
    *,
    obligation: VerificationObligation,
    routing: RoutingDecision,
    backend_obligation: BackendObligation,
    fingerprint: BackendEnvironmentFingerprint,
    input_format: str = "json",
) -> dict[str, Any]:
    """Return the full validated key component map for hardened cache reads."""
    from ovk.core.result_cache import build_backend_result_key_components

    return build_backend_result_key_components(
        obligation=obligation,
        routing=routing,
        backend_obligation=backend_obligation,
        fingerprint=fingerprint,
        input_format=input_format,
    )


def _error_raw(
    *,
    backend: str,
    backend_obligation_id: str,
    stage: str,
    exc: BaseException,
    started_at: str,
    started_perf: float,
) -> RawBackendExecution:
    finished_at = _utc_now_iso()
    raw = RawBackendExecution(
        backend=backend,
        backend_obligation_id=backend_obligation_id,
        termination="tool_error",
        native_execution=False,
        exit_code=1,
        stderr=f"{type(exc).__name__}: {exc}",
        raw_result={
            "status": "error",
            "error": {
                "category": type(exc).__name__,
                "message": str(exc),
                "stage": stage,
            },
        },
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=(time.perf_counter() - started_perf) * 1000.0,
    )
    return raw.model_copy(update=compute_raw_execution_digests(raw))


def _attempt_from_raw(
    *,
    raw: RawBackendExecution,
    required: bool,
) -> ExecutionAttempt:
    provisional = ExecutionAttempt(
        attempt_id="pending",
        backend_obligation_id=raw.backend_obligation_id,
        backend=raw.backend,
        required=required,
        started_at=raw.started_at or _utc_now_iso(),
        finished_at=raw.finished_at or _utc_now_iso(),
        duration_ms=float(raw.duration_ms or 0.0),
        termination=raw.termination,
        native_execution=raw.native_execution,
        tool_version=raw.tool_version,
        tool_digest=raw.tool_digest,
        worker_image_digest=raw.worker_image_digest,
        exit_code=raw.exit_code,
        stdout_digest=raw.stdout_digest,
        stderr_digest=raw.stderr_digest,
        raw_result_digest=raw.raw_result_digest,
    )
    return provisional.model_copy(update={"attempt_id": compute_attempt_id(provisional)})


class BackendControlPlane:
    """Execute selected backends for one obligation under an explicit budget."""

    def __init__(
        self,
        *,
        cache: ResultCache | None = None,
        worker: BackendWorker | None = None,
        use_hardened_cache: bool = True,
    ) -> None:
        if cache is not None:
            self._default_cache: ResultCache | None = cache
        elif use_hardened_cache:
            self._default_cache = ControlPlaneResultCache()
        else:
            self._default_cache = None
        self._worker = worker or LocalSubprocessWorker()

    @property
    def worker(self) -> BackendWorker:
        return self._worker

    def execute(
        self,
        obligation: VerificationObligation,
        routing: RoutingDecision,
        *,
        registry: BackendRegistry,
        cache: Any = _CACHE_UNSET,
    ) -> ObligationExecutionRecord:
        active_cache: ResultCache | None
        if cache is _CACHE_UNSET:
            active_cache = self._default_cache
        else:
            active_cache = cache
        budget = routing.budget
        backend_obligations: list[BackendObligation] = []
        attempts: list[ExecutionAttempt] = []
        results: list[NormalizedBackendResult] = []

        # Stable submission order: required first, then optional, each by backend id.
        selected = sorted(
            routing.selected,
            key=lambda item: (not item.required, item.backend),
        )

        for selection in selected:
            attempt, result, compiled = self._execute_one(
                obligation=obligation,
                routing=routing,
                selection_backend=selection.backend,
                required=selection.required,
                expected_guarantee=selection.expected_guarantee,
                registry=registry,
                budget=budget,
                cache=active_cache,
            )
            if compiled is not None:
                backend_obligations.append(compiled)
            attempts.append(attempt)
            results.append(result)

        # Deterministic result ordering by backend id.
        attempts = sorted(attempts, key=lambda item: item.backend)
        results = sorted(results, key=lambda item: item.backend)
        backend_obligations = sorted(backend_obligations, key=lambda item: item.backend)

        outcome = aggregate_results(
            obligation_id=obligation.obligation_id,
            selected=routing.selected,
            results=results,
            policy=routing.aggregation_policy,
            acceptable_guarantees=obligation.acceptable_guarantees,
            fallback_accepted=routing.fallback_policy.allow_fallback,
        )
        open_obligations: list[dict[str, Any]] = []
        if outcome.disagreement is not None:
            open_obligations.append(outcome.disagreement)
        if outcome.quality_error:
            open_obligations.append(
                {
                    "kind": "quality_error",
                    "obligation_id": obligation.obligation_id,
                    "reason": outcome.reason,
                }
            )
        for warning in outcome.warnings:
            open_obligations.append({"kind": "aggregation_warning", "message": warning})

        return ObligationExecutionRecord(
            obligation=obligation,
            routing=routing,
            backend_obligations=backend_obligations,
            attempts=attempts,
            results=results,
            aggregate_status=outcome.status,
            merge_recommendation=outcome.merge_recommendation,
            aggregation_reason=outcome.reason,
            open_obligations=open_obligations,
        )

    def _execute_one(
        self,
        *,
        obligation: VerificationObligation,
        routing: RoutingDecision,
        selection_backend: str,
        required: bool,
        expected_guarantee: str,
        registry: BackendRegistry,
        budget: ExecutionBudget,
        cache: ResultCache | None,
    ) -> tuple[ExecutionAttempt, NormalizedBackendResult, BackendObligation | None]:
        started_perf = time.perf_counter()
        started_at = _utc_now_iso()
        compiled: BackendObligation | None = None
        try:
            adapter = registry.require(selection_backend)
            if adapter.backend_id != selection_backend:
                raise BackendRegistryError(
                    f"adapter identity mismatch: expected {selection_backend}, "
                    f"got {adapter.backend_id}"
                )
            compiled = adapter.compile(obligation, routing)
            if compiled.backend != selection_backend:
                raise BackendRegistryError(
                    f"compiled backend {compiled.backend!r} does not match selection "
                    f"{selection_backend!r}"
                )
            if compiled.expected_guarantee != expected_guarantee and expected_guarantee:
                # Record expected guarantee from routing when adapter differs only by alias.
                compiled = compiled.model_copy(update={"expected_guarantee": expected_guarantee})

            fingerprint = adapter.fingerprint(compiled)
            components = control_plane_cache_components(
                obligation=obligation,
                routing=routing,
                backend_obligation=compiled,
                fingerprint=fingerprint,
            )
            key = control_plane_cache_key(
                obligation=obligation,
                routing=routing,
                backend_obligation=compiled,
                fingerprint=fingerprint,
            )
            if cache is not None:
                bind = getattr(cache, "bind_components", None)
                if callable(bind):
                    bind(key, components)
                cached = cache.get(key)
                if cached is not None:
                    attempt = ExecutionAttempt(
                        attempt_id="pending",
                        backend_obligation_id=compiled.backend_obligation_id,
                        backend=selection_backend,
                        required=required,
                        started_at=started_at,
                        finished_at=_utc_now_iso(),
                        duration_ms=(time.perf_counter() - started_perf) * 1000.0,
                        termination="completed",
                        native_execution=fingerprint.native_available,
                        tool_version=fingerprint.tool_version,
                        tool_digest=fingerprint.tool_digest,
                        worker_image_digest=fingerprint.worker_image_digest,
                        raw_result_digest=content_digest({"cache_hit": True, "key": key}),
                    )
                    attempt = attempt.model_copy(update={"attempt_id": compute_attempt_id(attempt)})
                    result = cached.model_copy(update={"attempt_id": attempt.attempt_id})
                    return attempt, result, compiled

            raw = self._run_adapter(adapter, compiled, budget)
            normalized = adapter.normalize(raw, compiled)
            attempt = _attempt_from_raw(raw=raw, required=required)
            result = normalized.model_copy(update={"attempt_id": attempt.attempt_id})
            if cache is not None:
                cache.put(
                    key,
                    result,
                    meta={
                        "environment_digest": fingerprint.environment_digest,
                        "raw_result_digest": raw.raw_result_digest,
                        "created_at": _utc_now_iso(),
                    },
                )
            return attempt, result, compiled
        except Exception as exc:  # noqa: BLE001 - isolate failures at backend boundary
            raw = _error_raw(
                backend=selection_backend,
                backend_obligation_id=(
                    compiled.backend_obligation_id if compiled is not None else "uncompiled"
                ),
                stage="execute",
                exc=exc,
                started_at=started_at,
                started_perf=started_perf,
            )
            attempt = _attempt_from_raw(raw=raw, required=required)
            result = NormalizedBackendResult(
                attempt_id=attempt.attempt_id,
                backend=selection_backend,
                status=VerificationStatus.ERROR,
                guarantee_type=expected_guarantee or "unknown",
                assumptions=[],
                limits=["backend execution failed at the control-plane boundary"],
                counterexamples=[
                    {
                        "summary": f"{type(exc).__name__}: {exc}",
                        "failure_mode": "backend_execution_error",
                    }
                ],
                generated_artifacts=[],
            )
            return attempt, result, compiled


    def _run_adapter(self, adapter: Any, compiled: BackendObligation, budget: ExecutionBudget) -> RawBackendExecution:
        """Invoke adapter.run, threading the worker when the adapter accepts it."""
        run = adapter.run
        try:
            parameters = inspect.signature(run).parameters
        except (TypeError, ValueError):
            parameters = {}
        if "worker" in parameters:
            return run(compiled, budget, worker=self._worker)
        return run(compiled, budget)


def compare_shadow_to_legacy(
    *,
    shadow: ObligationExecutionRecord,
    legacy_status: str,
    legacy_recommendation: str,
) -> dict[str, Any]:
    """Compare shadow control-plane outcome to authoritative legacy evidence."""
    shadow_status = shadow.aggregate_status.value
    shadow_recommendation = shadow.merge_recommendation.value
    agree_status = shadow_status == legacy_status
    agree_recommendation = shadow_recommendation == legacy_recommendation
    return {
        "kind": "shadow_comparison",
        "agreement": agree_status and agree_recommendation,
        "status_agreement": agree_status,
        "recommendation_agreement": agree_recommendation,
        "legacy": {
            "status": legacy_status,
            "merge_recommendation": legacy_recommendation,
            "authoritative": True,
        },
        "shadow": {
            "status": shadow_status,
            "merge_recommendation": shadow_recommendation,
            "authoritative": False,
            "routing_id": shadow.routing.routing_id,
            "obligation_id": shadow.obligation.obligation_id,
            "aggregation_reason": shadow.aggregation_reason,
        },
    }
