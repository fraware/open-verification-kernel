"""Deterministic self-protection backend (``self-protection-deterministic``)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

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
)
from ovk.core.execution_budget import BackendWorker
from ovk.core.models import VerificationStatus
from ovk.core.worker_runner import run_with_required_worker


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _input(obligation: VerificationObligation) -> dict[str, Any]:
    abstraction = obligation.abstraction
    if isinstance(abstraction.get("input"), dict):
        return dict(abstraction["input"])
    return dict(abstraction)


class SelfProtectionDeterministicAdapter:
    backend_id = "self-protection-deterministic"
    adapter_id = "ovk-adapter-self-protection-deterministic"
    adapter_version = "0.1.0"

    def manifest(self) -> BackendCapabilityManifest:
        return BackendCapabilityManifest(
            capability_id="self-protection-deterministic-v1",
            tool=BackendToolIdentity(
                name=self.backend_id,
                adapter=self.adapter_id,
                adapter_version=self.adapter_version,
                version=self.adapter_version,
            ),
            backend_class="policy_engine",
            guarantee=BackendGuaranteeDeclaration(
                type="policy_evaluation",
                meaning_of_pass="Trusted metadata shows the verification gate was preserved.",
                meaning_of_fail="An agent-authored change weakened self-protection controls.",
                meaning_of_unknown="Base/head metadata is missing or untrusted for a high-risk change.",
            ),
            input_languages=["json"],
            supported_domains=["self_protection", "ci_cd", "agent_authority"],
            supported_property_kinds=["invariant", "safety", "forbidden_configuration"],
            assumptions=["Before/after required-check metadata is trusted when marked trusted."],
            limits=["Does not execute OPA; deterministic Python policy only."],
            result_format="ovk.result.v1",
            counterexample_format="policy_violation",
            timeout_behavior="unknown",
        )

    def can_handle(
        self,
        obligation: VerificationObligation,
        context: ExecutionContext,
    ) -> BackendCapabilityAssessment:
        if obligation.lane != "self_protection":
            return BackendCapabilityAssessment(
                backend=self.backend_id,
                support="unsupported",
                score=0.0,
                guarantee_type="policy_evaluation",
                material_requirements_met=False,
                coverage_requirements_met=False,
                native_available=False,
                estimated_wall_time_seconds=1.0,
                estimated_memory_mb=64,
                reasons=["not a self_protection obligation"],
            )
        denied = set(context.budget.denied_backends if context.budget else [])
        allowed = set(context.budget.allowed_backends) if context.budget and context.budget.allowed_backends else None
        if self.backend_id in denied or (allowed is not None and self.backend_id not in allowed):
            return BackendCapabilityAssessment(
                backend=self.backend_id,
                support="unavailable",
                score=-1.0,
                guarantee_type="policy_evaluation",
                material_requirements_met=True,
                coverage_requirements_met=True,
                native_available=False,
                estimated_wall_time_seconds=1.0,
                estimated_memory_mb=64,
                reasons=["excluded by execution budget"],
            )
        trusted_meta = all(item.trusted for item in obligation.materials if item.kind == "branch_protection")
        materials_ok = bool(obligation.materials)
        coverage_ok = obligation.coverage.status in {"complete", "partial", "unknown"}
        score = 0.8 if trusted_meta else 0.55
        return BackendCapabilityAssessment(
            backend=self.backend_id,
            support="supported" if materials_ok else "partial",
            score=score,
            guarantee_type="policy_evaluation",
            material_requirements_met=materials_ok,
            coverage_requirements_met=coverage_ok,
            native_available=False,
            estimated_wall_time_seconds=1.0,
            estimated_memory_mb=64,
            reasons=[
                "deterministic self-protection policy",
                "trusted metadata" if trusted_meta else "untrusted or incomplete metadata",
            ],
        )

    def compile(self, obligation: VerificationObligation, routing: RoutingDecision) -> BackendObligation:
        payload = {"input": _input(obligation), "mode": "deterministic"}
        provisional = BackendObligation(
            backend_obligation_id="pending",
            obligation_id=obligation.obligation_id,
            routing_id=routing.routing_id,
            backend=self.backend_id,
            adapter_version=self.adapter_version,
            compiler_version=obligation.compiler_version,
            input_language="json",
            payload=payload,
            payload_digest=compute_payload_digest(payload),
            command_plan=["self_protection_deterministic"],
            environment_requirements={"native": False},
            expected_guarantee="policy_evaluation",
        )
        return provisional.model_copy(update={"backend_obligation_id": compute_backend_obligation_id(provisional)})

    def fingerprint(self, backend_obligation: BackendObligation) -> BackendEnvironmentFingerprint:
        return BackendEnvironmentFingerprint(
            backend=self.backend_id,
            adapter_version=self.adapter_version,
            environment_digest=content_digest(
                {"backend": self.backend_id, "payload": backend_obligation.payload_digest}
            ),
            tool_version=self.adapter_version,
            native_available=False,
        )

    def run(
        self,
        backend_obligation: BackendObligation,
        budget: ExecutionBudget,
        *,
        worker: BackendWorker | None = None,
    ) -> RawBackendExecution:
        return run_with_required_worker(
            worker,
            backend=self.backend_id,
            backend_obligation_id=backend_obligation.backend_obligation_id,
            adapter_version=self.adapter_version,
            evaluator_id="self-protection-deterministic",
            payload=dict(backend_obligation.payload),
            timeout_seconds=budget.per_backend_wall_time_seconds,
        )

    def normalize(
        self,
        raw: RawBackendExecution,
        backend_obligation: BackendObligation,
    ) -> NormalizedBackendResult:
        if raw.termination == "timeout":
            status = VerificationStatus.UNKNOWN
        else:
            try:
                status = VerificationStatus(str(raw.raw_result.get("status", "unknown")))
            except ValueError:
                status = VerificationStatus.UNKNOWN
        return NormalizedBackendResult(
            attempt_id="pending",
            backend=self.backend_id,
            status=status,
            guarantee_type=backend_obligation.expected_guarantee,
            assumptions=["Deterministic self-protection evaluator."],
            limits=["OPA native execution is a separate backend."],
            counterexamples=list(raw.raw_result.get("counterexamples") or []),
            generated_artifacts=[{"kind": "backend_provenance", "backend": self.backend_id, "native_execution": False}],
        )

    def explain(self, result: NormalizedBackendResult) -> HumanExplanation:
        if result.counterexamples:
            first = result.counterexamples[0]
            return HumanExplanation(
                summary=str(first.get("summary", "Self-protection violation.")),
                repair_hint="Restore required verification gates and trusted branch metadata.",
                failure_mode=str(first.get("failure_mode")) if first.get("failure_mode") else None,
            )
        if result.status == VerificationStatus.PASS:
            return HumanExplanation(
                summary="Self-protection controls preserved under trusted metadata.",
                repair_hint="No repair required.",
            )
        return HumanExplanation(
            summary=f"Self-protection deterministic backend returned {result.status.value}.",
            repair_hint="Supply trusted base and head required-check metadata.",
            failure_mode=result.status.value,
        )


ADAPTER = SelfProtectionDeterministicAdapter()
