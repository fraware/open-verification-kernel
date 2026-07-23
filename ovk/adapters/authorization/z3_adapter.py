"""Native Z3 authorization backend adapter (``z3-native``)."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from ovk.adapters.z3.executor import run_authorization_obligation_with_z3
from ovk.adapters.z3.obligation import build_authorization_obligation
from ovk.adapters.z3.result import normalize_z3_authorization_result
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


def z3_available() -> bool:
    try:
        import z3  # noqa: F401
    except Exception:
        return False
    return True


class Z3NativeAuthorizationAdapter:
    """Native SMT authorization backend. Does not silently fall back."""

    backend_id = "z3-native"
    adapter_id = "ovk-adapter-z3-native"
    adapter_version = "0.1.0"

    def manifest(self) -> BackendCapabilityManifest:
        return BackendCapabilityManifest(
            capability_id="z3-native-authorization-v1",
            tool=BackendToolIdentity(
                name=self.backend_id,
                adapter=self.adapter_id,
                adapter_version=self.adapter_version,
                version=None,
            ),
            backend_class="smt_solver",
            guarantee=BackendGuaranteeDeclaration(
                type="smt_refutation_search",
                meaning_of_pass="No satisfiable admin-route violation model under the SMT encoding.",
                meaning_of_fail="A satisfiable violation model was found.",
                meaning_of_unknown="Z3 was unavailable or returned unknown.",
            ),
            input_languages=["json"],
            supported_domains=["authorization"],
            supported_property_kinds=["access_control", "safety", "invariant"],
            assumptions=["Route reachability abstraction faithfully encodes the change."],
            limits=["Requires z3-solver; timeouts and unknown remain non-pass."],
            result_format="ovk.result.v1",
            counterexample_format="smt_model",
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
                guarantee_type="smt_refutation_search",
                material_requirements_met=False,
                coverage_requirements_met=False,
                native_available=False,
                estimated_wall_time_seconds=5.0,
                estimated_memory_mb=256,
                reasons=["not an authorization obligation"],
            )
        denied = set(context.budget.denied_backends if context.budget else [])
        allowed = set(context.budget.allowed_backends) if context.budget and context.budget.allowed_backends else None
        native = z3_available()
        if self.backend_id in denied or (allowed is not None and self.backend_id not in allowed):
            return BackendCapabilityAssessment(
                backend=self.backend_id,
                support="unavailable",
                score=-1.0,
                guarantee_type="smt_refutation_search",
                material_requirements_met=True,
                coverage_requirements_met=True,
                native_available=native,
                estimated_wall_time_seconds=5.0,
                estimated_memory_mb=256,
                reasons=["excluded by execution budget"],
            )
        if not native:
            return BackendCapabilityAssessment(
                backend=self.backend_id,
                support="unavailable",
                score=-1.0,
                guarantee_type="smt_refutation_search",
                material_requirements_met=True,
                coverage_requirements_met=obligation.coverage.status in {"complete", "partial"},
                native_available=False,
                estimated_wall_time_seconds=5.0,
                estimated_memory_mb=256,
                reasons=["z3-solver is not installed"],
            )
        materials_ok = bool(obligation.materials) and bool(obligation.abstraction)
        coverage_ok = obligation.coverage.status in {"complete", "partial"}
        return BackendCapabilityAssessment(
            backend=self.backend_id,
            support="supported" if materials_ok and coverage_ok else "partial",
            score=0.95 if coverage_ok else 0.5,
            guarantee_type="smt_refutation_search",
            material_requirements_met=materials_ok,
            coverage_requirements_met=coverage_ok,
            native_available=True,
            estimated_wall_time_seconds=5.0,
            estimated_memory_mb=256,
            reasons=["native z3 authorization backend available"],
        )

    def compile(
        self,
        obligation: VerificationObligation,
        routing: RoutingDecision,
    ) -> BackendObligation:
        data = _authorization_input(obligation)
        payload = {"input": data, "mode": "z3-native"}
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
            command_plan=["z3-solver", "authorization_reachability"],
            environment_requirements={"native": True, "binary": "z3-solver"},
            expected_guarantee="smt_refutation_search",
        )
        return provisional.model_copy(
            update={"backend_obligation_id": compute_backend_obligation_id(provisional)}
        )

    def fingerprint(self, backend_obligation: BackendObligation) -> BackendEnvironmentFingerprint:
        native = z3_available()
        tool_version = None
        if native:
            try:
                import z3

                tool_version = getattr(z3, "get_version_string", lambda: None)()
            except Exception:
                tool_version = "unknown"
        return BackendEnvironmentFingerprint(
            backend=self.backend_id,
            adapter_version=self.adapter_version,
            environment_digest=content_digest(
                {
                    "backend": self.backend_id,
                    "native": native,
                    "tool_version": tool_version,
                    "payload": backend_obligation.payload_digest,
                }
            ),
            tool_version=tool_version,
            native_available=native,
        )

    def run(
        self,
        backend_obligation: BackendObligation,
        budget: ExecutionBudget,
    ) -> RawBackendExecution:
        started = time.perf_counter()
        started_at = _utc_now_iso()
        data = dict(backend_obligation.payload.get("input") or {})
        if budget.per_backend_wall_time_seconds <= 0:
            raw = RawBackendExecution(
                backend=self.backend_id,
                backend_obligation_id=backend_obligation.backend_obligation_id,
                termination="timeout",
                native_execution=True,
                exit_code=1,
                raw_result={"status": "unknown", "reason": "budget timeout", "models": []},
                started_at=started_at,
                finished_at=_utc_now_iso(),
                duration_ms=(time.perf_counter() - started) * 1000.0,
                tool_version=self.adapter_version,
            )
            return raw.model_copy(update=compute_raw_execution_digests(raw))

        issues = validate_authorization_input(data)
        if issues:
            raw = RawBackendExecution(
                backend=self.backend_id,
                backend_obligation_id=backend_obligation.backend_obligation_id,
                termination="invalid_output",
                native_execution=False,
                exit_code=1,
                raw_result={"status": "unknown", "reason": "malformed input", "issues": issues, "models": []},
                started_at=started_at,
                finished_at=_utc_now_iso(),
                duration_ms=(time.perf_counter() - started) * 1000.0,
                tool_version=self.adapter_version,
            )
            return raw.model_copy(update=compute_raw_execution_digests(raw))

        if not z3_available():
            # Explicit non-fallback: native adapter reports unavailable/unknown.
            raw = RawBackendExecution(
                backend=self.backend_id,
                backend_obligation_id=backend_obligation.backend_obligation_id,
                termination="tool_unavailable",
                native_execution=False,
                exit_code=1,
                raw_result={
                    "status": "unknown",
                    "reason": "z3-solver is not installed",
                    "models": [],
                },
                started_at=started_at,
                finished_at=_utc_now_iso(),
                duration_ms=(time.perf_counter() - started) * 1000.0,
                tool_version=self.adapter_version,
            )
            return raw.model_copy(update=compute_raw_execution_digests(raw))

        auth_obligation = build_authorization_obligation(data)
        native_raw = run_authorization_obligation_with_z3(auth_obligation)
        normalized = normalize_z3_authorization_result(native_raw)
        raw = RawBackendExecution(
            backend=self.backend_id,
            backend_obligation_id=backend_obligation.backend_obligation_id,
            termination="completed",
            native_execution=True,
            exit_code=0,
            raw_result={
                "status": normalized["status"],
                "reason": native_raw.get("reason"),
                "models": native_raw.get("models", []),
                "counterexamples": normalized.get("counterexamples", []),
            },
            started_at=started_at,
            finished_at=_utc_now_iso(),
            duration_ms=(time.perf_counter() - started) * 1000.0,
            tool_version=self.adapter_version,
        )
        return raw.model_copy(update=compute_raw_execution_digests(raw))

    def normalize(
        self,
        raw: RawBackendExecution,
        backend_obligation: BackendObligation,
    ) -> NormalizedBackendResult:
        if raw.termination == "timeout":
            status = VerificationStatus.UNKNOWN
        elif raw.termination == "tool_unavailable":
            status = VerificationStatus.UNKNOWN
        elif raw.termination in {"tool_error"}:
            status = VerificationStatus.ERROR
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
            assumptions=["Native z3-solver encoding of route reachability."],
            limits=["Unknown and timeout never become pass."],
            counterexamples=list(raw.raw_result.get("counterexamples") or []),
            generated_artifacts=[
                {
                    "kind": "backend_provenance",
                    "backend": self.backend_id,
                    "native_execution": raw.native_execution,
                    "termination": raw.termination,
                }
            ],
        )

    def explain(self, result: NormalizedBackendResult) -> HumanExplanation:
        if result.counterexamples:
            return HumanExplanation(
                summary=str(result.counterexamples[0].get("summary", "SMT violation model found.")),
                repair_hint="Close the reported admin-route reachability path.",
                failure_mode=str(result.counterexamples[0].get("failure_mode", "admin_route_bypass")),
            )
        if result.status == VerificationStatus.PASS:
            return HumanExplanation(
                summary="Z3 found no satisfiable authorization violation.",
                repair_hint="No repair required.",
            )
        return HumanExplanation(
            summary=f"Z3-native backend returned {result.status.value}.",
            repair_hint="Install z3-solver or select an accepted fallback backend via policy.",
            failure_mode=result.status.value,
        )


def _authorization_input(obligation: VerificationObligation) -> dict[str, Any]:
    abstraction = obligation.abstraction
    if isinstance(abstraction.get("input"), dict):
        return dict(abstraction["input"])
    return dict(abstraction)


ADAPTER = Z3NativeAuthorizationAdapter()
