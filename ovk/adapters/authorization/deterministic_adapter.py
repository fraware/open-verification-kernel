"""Deterministic authorization backend adapter (``authorization-deterministic``)."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from ovk.adapters.z3.counterexample import counterexamples_from_obligation
from ovk.adapters.z3.obligation import build_authorization_obligation
from ovk.adapters.z3.validation import validate_authorization_input
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
from ovk.core.models import VerificationStatus


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuthorizationDeterministicAdapter:
    """Deterministic witness translation backend for authorization."""

    backend_id = "authorization-deterministic"
    adapter_id = "ovk-adapter-authorization-deterministic"
    adapter_version = "0.1.0"

    def manifest(self) -> BackendCapabilityManifest:
        return BackendCapabilityManifest(
            capability_id="authorization-deterministic-v1",
            tool=BackendToolIdentity(
                name=self.backend_id,
                adapter=self.adapter_id,
                adapter_version=self.adapter_version,
                version=self.adapter_version,
            ),
            backend_class="custom",
            guarantee=BackendGuaranteeDeclaration(
                type="deterministic_witness",
                meaning_of_pass="No deterministic violation witness exists in the abstraction.",
                meaning_of_fail="A deterministic violation witness was found.",
                meaning_of_unknown="The authorization abstraction was malformed or incomplete.",
            ),
            input_languages=["json"],
            supported_domains=["authorization"],
            supported_property_kinds=["access_control", "safety", "invariant"],
            assumptions=[
                "Route reachability abstraction is supplied by the neutral compiler.",
            ],
            limits=[
                "Weaker than native SMT refutation; does not execute z3-solver.",
            ],
            result_format="ovk.result.v1",
            counterexample_format="authorization_witness",
            timeout_behavior="unknown",
        )

    def can_handle(
        self,
        obligation: VerificationObligation,
        context: ExecutionContext,
    ) -> BackendCapabilityAssessment:
        if obligation.lane != "authorization":
            return BackendCapabilityAssessment(
                backend=self.backend_id,
                support="unsupported",
                score=0.0,
                guarantee_type="deterministic_witness",
                material_requirements_met=False,
                coverage_requirements_met=False,
                native_available=False,
                estimated_wall_time_seconds=1.0,
                estimated_memory_mb=64,
                reasons=["not an authorization obligation"],
            )
        denied = set(context.budget.denied_backends if context.budget else [])
        allowed = set(context.budget.allowed_backends) if context.budget and context.budget.allowed_backends else None
        if self.backend_id in denied or (allowed is not None and self.backend_id not in allowed):
            return BackendCapabilityAssessment(
                backend=self.backend_id,
                support="unavailable",
                score=-1.0,
                guarantee_type="deterministic_witness",
                material_requirements_met=True,
                coverage_requirements_met=True,
                native_available=False,
                estimated_wall_time_seconds=1.0,
                estimated_memory_mb=64,
                reasons=["excluded by execution budget"],
            )
        materials_ok = bool(obligation.materials) and bool(obligation.abstraction)
        coverage_ok = obligation.coverage.status in {"complete", "partial"}
        score = 0.75 if coverage_ok else 0.45
        return BackendCapabilityAssessment(
            backend=self.backend_id,
            support="supported" if materials_ok else "partial",
            score=score,
            guarantee_type="deterministic_witness",
            material_requirements_met=materials_ok,
            coverage_requirements_met=coverage_ok,
            native_available=False,
            estimated_wall_time_seconds=1.0,
            estimated_memory_mb=64,
            reasons=["deterministic authorization witness backend"],
        )

    def compile(
        self,
        obligation: VerificationObligation,
        routing: RoutingDecision,
    ) -> BackendObligation:
        data = _authorization_input(obligation)
        payload = {"input": data, "mode": "deterministic"}
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
            command_plan=["authorization_deterministic_witness"],
            environment_requirements={"native": False},
            expected_guarantee="deterministic_witness",
        )
        return provisional.model_copy(
            update={"backend_obligation_id": compute_backend_obligation_id(provisional)}
        )

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
    ) -> RawBackendExecution:
        started = time.perf_counter()
        started_at = _utc_now_iso()
        data = dict(backend_obligation.payload.get("input") or {})
        issues = validate_authorization_input(data)
        if issues:
            raw_result = {
                "status": "unknown",
                "reason": "malformed authorization input",
                "issues": issues,
                "models": [],
            }
            termination = "invalid_output"
        else:
            auth_obligation = build_authorization_obligation(data)
            counterexamples = counterexamples_from_obligation(auth_obligation)
            raw_result = {
                "status": "fail" if counterexamples else "pass",
                "reason": (
                    "deterministic violation witness found"
                    if counterexamples
                    else "no deterministic violation witness found"
                ),
                "models": counterexamples,
                "counterexamples": counterexamples,
            }
            termination = "completed"
        # Soft timeout signal for tests: budget of 0 forces timeout.
        duration_ms = (time.perf_counter() - started) * 1000.0
        if budget.per_backend_wall_time_seconds <= 0:
            termination = "timeout"
            raw_result = {
                "status": "unknown",
                "reason": "budget timeout",
                "models": [],
            }
        raw = RawBackendExecution(
            backend=self.backend_id,
            backend_obligation_id=backend_obligation.backend_obligation_id,
            termination=termination,  # type: ignore[arg-type]
            native_execution=False,
            exit_code=0 if termination == "completed" else 1,
            raw_result=raw_result,
            started_at=started_at,
            finished_at=_utc_now_iso(),
            duration_ms=duration_ms,
            tool_version=self.adapter_version,
        )
        return raw.model_copy(update=compute_raw_execution_digests(raw))

    def normalize(
        self,
        raw: RawBackendExecution,
        backend_obligation: BackendObligation,
    ) -> NormalizedBackendResult:
        status_text = str(raw.raw_result.get("status", "unknown"))
        if raw.termination == "timeout":
            status = VerificationStatus.UNKNOWN
        elif raw.termination in {"tool_error", "invalid_output"} and status_text != "unknown":
            status = VerificationStatus.ERROR
        else:
            try:
                status = VerificationStatus(status_text)
            except ValueError:
                status = VerificationStatus.UNKNOWN
        return NormalizedBackendResult(
            attempt_id="pending",
            backend=self.backend_id,
            status=status,
            guarantee_type=backend_obligation.expected_guarantee,
            assumptions=["Deterministic witness translation; no native SMT solver."],
            limits=["Weaker than z3-native smt_refutation_search."],
            counterexamples=list(raw.raw_result.get("counterexamples") or raw.raw_result.get("models") or []),
            generated_artifacts=[
                {
                    "kind": "backend_provenance",
                    "backend": self.backend_id,
                    "native_execution": False,
                }
            ],
        )

    def explain(self, result: NormalizedBackendResult) -> HumanExplanation:
        if result.counterexamples:
            return HumanExplanation(
                summary=str(result.counterexamples[0].get("summary", "Authorization violation.")),
                repair_hint="Restore admin-only protection on the reported route.",
                failure_mode=str(result.counterexamples[0].get("failure_mode", "admin_route_bypass")),
            )
        if result.status == VerificationStatus.PASS:
            return HumanExplanation(
                summary="No deterministic authorization violation witness found.",
                repair_hint="No repair required.",
            )
        return HumanExplanation(
            summary=f"Authorization deterministic backend returned {result.status.value}.",
            repair_hint="Inspect the route abstraction and validation issues.",
            failure_mode=result.status.value,
        )


def _authorization_input(obligation: VerificationObligation) -> dict[str, Any]:
    abstraction = obligation.abstraction
    if isinstance(abstraction.get("input"), dict):
        return dict(abstraction["input"])
    return dict(abstraction)


ADAPTER = AuthorizationDeterministicAdapter()
