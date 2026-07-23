"""Shared base for legacy lane evaluator wrappers.

Wrappers call existing lane evaluators; they do not copy evaluation logic.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable

from ovk.core.bundle import content_digest
from ovk.core.execution_models import (
    BackendCapabilityAssessment,
    BackendCapabilityManifest,
    BackendEnvironmentFingerprint,
    BackendGuaranteeDeclaration,
    BackendObligation,
    BackendToolIdentity,
    ExecutionBudget,
    ExecutionContext,
    HumanExplanation,
    NormalizedBackendResult,
    RawBackendExecution,
    RoutingDecision,
    VerificationObligation,
    compute_backend_obligation_id,
    compute_payload_digest,
    compute_raw_execution_digests,
)
from ovk.core.models import VerificationEvidence, VerificationStatus


EvaluatorFn = Callable[..., VerificationEvidence]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class LaneEvaluatorAdapter:
    """Adapter that delegates execution to an existing lane evaluator."""

    backend_id: str
    adapter_id: str
    adapter_version: str
    lane: str
    guarantee_type: str
    backend_class: str
    supported_domains: list[str]
    supported_property_kinds: list[str]
    input_languages: list[str]
    uses_native_execution: bool
    has_deterministic_fallback: bool
    fallback_semantically_weaker: bool
    requires_network: bool
    reads_repository_files: bool
    writes_generated_files: bool
    processes_untrusted_input_safely: bool
    supported_os: list[str]
    supported_arch: list[str]
    assumptions: list[str]
    limits: list[str]
    _evaluator: EvaluatorFn

    def __init__(self, *, evaluator: EvaluatorFn) -> None:
        self._evaluator = evaluator

    def manifest(self) -> BackendCapabilityManifest:
        return BackendCapabilityManifest(
            capability_id=f"{self.backend_id}-v1",
            tool=BackendToolIdentity(
                name=self.backend_id,
                adapter=self.adapter_id,
                adapter_version=self.adapter_version,
                version=self.adapter_version,
            ),
            backend_class=self.backend_class,
            guarantee=BackendGuaranteeDeclaration(
                type=self.guarantee_type,
                meaning_of_pass="The lane evaluator reported pass under stated assumptions.",
                meaning_of_fail="The lane evaluator reported a concrete violation.",
                meaning_of_unknown="The lane evaluator could not decide from available materials.",
            ),
            input_languages=list(self.input_languages),
            supported_domains=list(self.supported_domains),
            supported_property_kinds=list(self.supported_property_kinds),
            assumptions=list(self.assumptions),
            limits=list(self.limits),
            result_format="ovk.evidence.v1",
            counterexample_format="lane_counterexample",
            timeout_behavior="unknown",
        )

    def can_handle(
        self,
        obligation: VerificationObligation,
        context: ExecutionContext,
    ) -> BackendCapabilityAssessment:
        lane_match = obligation.lane == self.lane
        domain_ok = obligation.lane in self.supported_domains or any(
            domain in self.supported_domains for domain in (obligation.lane, obligation.property_kind)
        )
        kind_ok = obligation.property_kind in self.supported_property_kinds
        materials_ok = bool(obligation.materials) or bool(obligation.abstraction)
        coverage_ok = obligation.coverage.status in {"complete", "partial", "unknown", "inapplicable"}
        reasons: list[str] = []
        if not lane_match:
            reasons.append(f"obligation lane {obligation.lane!r} does not match adapter lane {self.lane!r}")
            support = "unsupported"
            score = 0.0
        elif not materials_ok:
            reasons.append("obligation materials/abstraction missing")
            support = "partial"
            score = 0.25
        elif lane_match and kind_ok:
            reasons.append(f"lane wrapper for {self.lane} supports property kind {obligation.property_kind}")
            support = "supported"
            score = 0.9
        elif lane_match and domain_ok:
            reasons.append(f"lane wrapper for {self.lane} matches lane with partial property support")
            support = "partial"
            score = 0.55
        else:
            reasons.append(f"lane wrapper for {self.lane} matches lane")
            support = "supported"
            score = 0.8

        denied = set(context.budget.denied_backends if context.budget else [])
        allowed = set(context.budget.allowed_backends) if context.budget and context.budget.allowed_backends else None
        if self.backend_id in denied or (allowed is not None and self.backend_id not in allowed):
            reasons.append("excluded by execution budget")
            support = "unavailable"
            score = -1.0

        return BackendCapabilityAssessment(
            backend=self.backend_id,
            support=support,  # type: ignore[arg-type]
            score=score,
            guarantee_type=self.guarantee_type,
            material_requirements_met=materials_ok,
            coverage_requirements_met=coverage_ok,
            native_available=self.uses_native_execution,
            estimated_wall_time_seconds=5.0,
            estimated_memory_mb=256,
            reasons=reasons,
        )

    def compile(
        self,
        obligation: VerificationObligation,
        routing: RoutingDecision,
    ) -> BackendObligation:
        payload = {
            "lane": self.lane,
            "abstraction": dict(obligation.abstraction),
            "subject": obligation.subject.model_dump(mode="json"),
            "intent_id": obligation.intent_id,
            "property_kind": obligation.property_kind,
            "metadata": {
                "compiler_id": obligation.compiler_id,
                "compiler_version": obligation.compiler_version,
            },
        }
        provisional = BackendObligation(
            backend_obligation_id="pending",
            obligation_id=obligation.obligation_id,
            routing_id=routing.routing_id,
            backend=self.backend_id,
            adapter_version=self.adapter_version,
            compiler_version=obligation.compiler_version,
            input_language=self.input_languages[0] if self.input_languages else "json",
            payload=payload,
            payload_digest=compute_payload_digest(payload),
            command_plan=[f"evaluate_lane:{self.lane}"],
            environment_requirements={
                "uses_native_execution": self.uses_native_execution,
                "has_deterministic_fallback": self.has_deterministic_fallback,
                "fallback_semantically_weaker": self.fallback_semantically_weaker,
                "requires_network": self.requires_network,
                "reads_repository_files": self.reads_repository_files,
                "writes_generated_files": self.writes_generated_files,
                "processes_untrusted_input_safely": self.processes_untrusted_input_safely,
                "supported_os": list(self.supported_os),
                "supported_arch": list(self.supported_arch),
            },
            expected_guarantee=self.guarantee_type,
        )
        return provisional.model_copy(
            update={"backend_obligation_id": compute_backend_obligation_id(provisional)}
        )

    def fingerprint(self, backend_obligation: BackendObligation) -> BackendEnvironmentFingerprint:
        env_payload = {
            "backend": self.backend_id,
            "adapter_version": self.adapter_version,
            "payload_digest": backend_obligation.payload_digest,
            "environment_requirements": backend_obligation.environment_requirements,
        }
        return BackendEnvironmentFingerprint(
            backend=self.backend_id,
            adapter_version=self.adapter_version,
            environment_digest=content_digest(env_payload),
            tool_version=self.adapter_version,
            native_available=self.uses_native_execution,
        )

    def run(
        self,
        backend_obligation: BackendObligation,
        budget: ExecutionBudget,
    ) -> RawBackendExecution:
        started = time.perf_counter()
        started_at = _utc_now_iso()
        subject = backend_obligation.payload.get("subject") or {}
        data = dict(backend_obligation.payload.get("abstraction") or {})
        # Lane evaluators historically receive the lane input object directly.
        if "input" in data and isinstance(data["input"], dict):
            lane_input = dict(data["input"])
        else:
            lane_input = data
        try:
            evidence = self._evaluator(
                lane_input,
                repo=str(subject.get("repo", "unknown/repo")),
                head_sha=str(subject.get("head_sha", "unknown")),
                base_sha=subject.get("base_sha"),
            )
            termination = "completed"
            exit_code = 0
            raw_result = {
                "evidence": evidence.model_dump(mode="json"),
                "status": evidence.backend_claims[0].status.value if evidence.backend_claims else "unknown",
            }
            stderr = None
        except Exception as exc:  # noqa: BLE001 - convert at backend boundary
            termination = "tool_error"
            exit_code = 1
            raw_result = {
                "status": "error",
                "error": {
                    "category": type(exc).__name__,
                    "message": str(exc),
                    "stage": "run",
                },
            }
            stderr = str(exc)
            evidence = None  # type: ignore[assignment]

        finished_at = _utc_now_iso()
        duration_ms = (time.perf_counter() - started) * 1000.0
        # Soft budget recording only; hard isolation arrives with the control plane.
        if duration_ms > budget.per_backend_wall_time_seconds * 1000.0 and termination == "completed":
            termination = "timeout"
            raw_result["status"] = "unknown"
            raw_result["timeout"] = True

        raw = RawBackendExecution(
            backend=self.backend_id,
            backend_obligation_id=backend_obligation.backend_obligation_id,
            termination=termination,  # type: ignore[arg-type]
            native_execution=False,
            exit_code=exit_code,
            stdout=None,
            stderr=stderr,
            raw_result=raw_result,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            tool_version=self.adapter_version,
        )
        digests = compute_raw_execution_digests(raw)
        return raw.model_copy(update=digests)

    def normalize(
        self,
        raw: RawBackendExecution,
        backend_obligation: BackendObligation,
    ) -> NormalizedBackendResult:
        status_raw = str(raw.raw_result.get("status", "unknown"))
        try:
            status = VerificationStatus(status_raw)
        except ValueError:
            status = VerificationStatus.UNKNOWN
        if raw.termination in {"timeout", "resource_exhausted", "tool_unavailable", "cancelled"}:
            status = VerificationStatus.UNKNOWN
        elif raw.termination in {"tool_error", "invalid_output"}:
            status = VerificationStatus.ERROR

        evidence_payload = raw.raw_result.get("evidence")
        counterexamples: list[dict[str, Any]] = []
        assumptions = list(self.assumptions)
        limits = list(self.limits)
        generated: list[dict[str, Any]] = []
        if isinstance(evidence_payload, dict):
            counterexamples = list(evidence_payload.get("counterexamples") or [])
            claims = evidence_payload.get("backend_claims") or []
            if claims and isinstance(claims[0], dict):
                assumptions = list(claims[0].get("assumptions") or assumptions)
                limits = list(claims[0].get("limits") or limits)
            generated = list(evidence_payload.get("generated_artifacts") or [])

        return NormalizedBackendResult(
            attempt_id="pending",
            backend=self.backend_id,
            status=status,
            guarantee_type=backend_obligation.expected_guarantee,
            assumptions=assumptions,
            limits=limits,
            counterexamples=counterexamples,
            generated_artifacts=generated,
        )

    def explain(self, result: NormalizedBackendResult) -> HumanExplanation:
        if result.counterexamples:
            first = result.counterexamples[0]
            return HumanExplanation(
                summary=str(first.get("summary", f"{self.backend_id} reported a violation.")),
                repair_hint="Review the counterexample and restore the violated invariant.",
                failure_mode=str(first.get("failure_mode")) if first.get("failure_mode") else None,
            )
        if result.status == VerificationStatus.PASS:
            return HumanExplanation(
                summary=f"{self.backend_id} reported pass under stated assumptions.",
                repair_hint="No repair required.",
            )
        return HumanExplanation(
            summary=f"{self.backend_id} result status is {result.status.value}.",
            repair_hint="Inspect materials, coverage, and backend logs before merging.",
            failure_mode=result.status.value,
        )
