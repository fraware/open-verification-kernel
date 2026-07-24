"""Native OPA self-protection backend (``opa-native``)."""

from __future__ import annotations

import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ovk.adapters.opa.optional_runner import run_opa_policy
from ovk.adapters.opa.policy_assets import resolve_self_protection_policy_path
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
from ovk.core.execution_budget import BackendWorker
from ovk.core.models import VerificationStatus


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def opa_available() -> bool:
    from shutil import which

    return which("opa") is not None


def _input(obligation: VerificationObligation) -> dict[str, Any]:
    abstraction = obligation.abstraction
    if isinstance(abstraction.get("input"), dict):
        return dict(abstraction["input"])
    return dict(abstraction)


class OpaNativeSelfProtectionAdapter:
    backend_id = "opa-native"
    adapter_id = "ovk-adapter-opa-native"
    adapter_version = "0.1.0"

    def manifest(self) -> BackendCapabilityManifest:
        return BackendCapabilityManifest(
            capability_id="opa-native-self-protection-v1",
            tool=BackendToolIdentity(
                name=self.backend_id,
                adapter=self.adapter_id,
                adapter_version=self.adapter_version,
            ),
            backend_class="policy_engine",
            guarantee=BackendGuaranteeDeclaration(
                type="policy_evaluation",
                meaning_of_pass="OPA reported no self-protection violations.",
                meaning_of_fail="OPA reported one or more self-protection violations.",
                meaning_of_unknown="OPA was unavailable, timed out, or returned invalid output.",
            ),
            input_languages=["json", "rego"],
            supported_domains=["self_protection", "ci_cd", "agent_authority"],
            supported_property_kinds=["invariant", "safety", "forbidden_configuration"],
            assumptions=["Rego policy matches the deterministic self-protection intent."],
            limits=["Requires opa binary; never silently falls back to deterministic pass."],
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
                estimated_wall_time_seconds=5.0,
                estimated_memory_mb=128,
                reasons=["not a self_protection obligation"],
            )
        denied = set(context.budget.denied_backends if context.budget else [])
        allowed = set(context.budget.allowed_backends) if context.budget and context.budget.allowed_backends else None
        native = opa_available()
        if self.backend_id in denied or (allowed is not None and self.backend_id not in allowed):
            return BackendCapabilityAssessment(
                backend=self.backend_id,
                support="unavailable",
                score=-1.0,
                guarantee_type="policy_evaluation",
                material_requirements_met=True,
                coverage_requirements_met=True,
                native_available=native,
                estimated_wall_time_seconds=5.0,
                estimated_memory_mb=128,
                reasons=["excluded by execution budget"],
            )
        if not native:
            return BackendCapabilityAssessment(
                backend=self.backend_id,
                support="unavailable",
                score=-1.0,
                guarantee_type="policy_evaluation",
                material_requirements_met=True,
                coverage_requirements_met=True,
                native_available=False,
                estimated_wall_time_seconds=5.0,
                estimated_memory_mb=128,
                reasons=["opa binary not found"],
            )
        return BackendCapabilityAssessment(
            backend=self.backend_id,
            support="supported",
            score=0.92,
            guarantee_type="policy_evaluation",
            material_requirements_met=bool(obligation.materials),
            coverage_requirements_met=obligation.coverage.status in {"complete", "partial", "unknown"},
            native_available=True,
            estimated_wall_time_seconds=5.0,
            estimated_memory_mb=128,
            reasons=["native OPA self-protection backend available"],
        )

    def compile(self, obligation: VerificationObligation, routing: RoutingDecision) -> BackendObligation:
        payload = {"input": _input(obligation), "mode": "opa-native"}
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
            command_plan=["opa", "eval", "data.ovk.self_protection.violation"],
            environment_requirements={"native": True, "binary": "opa"},
            expected_guarantee="policy_evaluation",
        )
        return provisional.model_copy(update={"backend_obligation_id": compute_backend_obligation_id(provisional)})

    def fingerprint(self, backend_obligation: BackendObligation) -> BackendEnvironmentFingerprint:
        return BackendEnvironmentFingerprint(
            backend=self.backend_id,
            adapter_version=self.adapter_version,
            environment_digest=content_digest(
                {"backend": self.backend_id, "opa": opa_available(), "payload": backend_obligation.payload_digest}
            ),
            tool_version="opa" if opa_available() else None,
            native_available=opa_available(),
        )

    def run(
        self,
        backend_obligation: BackendObligation,
        budget: ExecutionBudget,
        *,
        worker: BackendWorker | None = None,
    ) -> RawBackendExecution:
        started = time.perf_counter()
        started_at = _utc_now_iso()
        timeout = max(1, int(budget.per_backend_wall_time_seconds))
        if budget.per_backend_wall_time_seconds <= 0:
            raw = RawBackendExecution(
                backend=self.backend_id,
                backend_obligation_id=backend_obligation.backend_obligation_id,
                termination="timeout",
                native_execution=False,
                exit_code=1,
                raw_result={"status": "unknown", "reason": "budget timeout", "counterexamples": []},
                started_at=started_at,
                finished_at=_utc_now_iso(),
                duration_ms=(time.perf_counter() - started) * 1000.0,
            )
            return raw.model_copy(update=compute_raw_execution_digests(raw))

        if worker is None:
            raw = RawBackendExecution(
                backend=self.backend_id,
                backend_obligation_id=backend_obligation.backend_obligation_id,
                termination="tool_error",
                native_execution=False,
                exit_code=1,
                raw_result={
                    "status": "error",
                    "reason": "authoritative OPA adapter requires BackendWorker",
                    "counterexamples": [],
                },
                started_at=started_at,
                finished_at=_utc_now_iso(),
                duration_ms=(time.perf_counter() - started) * 1000.0,
            )
            return raw.model_copy(update=compute_raw_execution_digests(raw))

        if not opa_available():
            raw = RawBackendExecution(
                backend=self.backend_id,
                backend_obligation_id=backend_obligation.backend_obligation_id,
                termination="tool_unavailable",
                native_execution=False,
                exit_code=1,
                raw_result={"status": "unknown", "reason": "opa binary not found", "counterexamples": []},
                started_at=started_at,
                finished_at=_utc_now_iso(),
                duration_ms=(time.perf_counter() - started) * 1000.0,
            )
            return raw.model_copy(update=compute_raw_execution_digests(raw))

        data = dict(backend_obligation.payload.get("input") or {})
        policy_path = resolve_self_protection_policy_path()
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.json"
            input_path.write_text(json.dumps(data), encoding="utf-8")
            result = run_opa_policy(
                policy_path=policy_path,
                input_path=input_path,
                timeout_seconds=timeout,
                worker=worker,
                cwd=Path(tmp),
            )

        status = str(result.get("status", "unknown"))
        violations = result.get("violations") or []
        counterexamples = [
            {"summary": str(item), "failure_mode": "opa_policy_violation"}
            if not isinstance(item, dict)
            else item
            for item in violations
        ]
        termination = "completed"
        if status == "unknown" and "timed out" in str(result.get("reason", "")):
            termination = "timeout"
        elif status == "unknown" and "not found" in str(result.get("reason", "")):
            termination = "tool_unavailable"
        elif status == "error":
            termination = "tool_error"

        raw = RawBackendExecution(
            backend=self.backend_id,
            backend_obligation_id=backend_obligation.backend_obligation_id,
            termination=termination,  # type: ignore[arg-type]
            native_execution=termination == "completed",
            exit_code=0 if status == "pass" else 1,
            raw_result={
                "status": status,
                "reason": result.get("reason"),
                "counterexamples": counterexamples,
            },
            started_at=started_at,
            finished_at=_utc_now_iso(),
            duration_ms=(time.perf_counter() - started) * 1000.0,
            tool_version="opa",
        )
        return raw.model_copy(update=compute_raw_execution_digests(raw))

    def normalize(
        self,
        raw: RawBackendExecution,
        backend_obligation: BackendObligation,
    ) -> NormalizedBackendResult:
        if raw.termination in {"timeout", "tool_unavailable"}:
            status = VerificationStatus.UNKNOWN
        elif raw.termination == "tool_error":
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
            assumptions=["Native OPA evaluation of packaged Rego policy."],
            limits=["Unavailable OPA remains unknown; no implicit deterministic pass."],
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
                summary=str(result.counterexamples[0].get("summary", "OPA reported a violation.")),
                repair_hint="Restore the verification gate and re-run with trusted metadata.",
                failure_mode=str(result.counterexamples[0].get("failure_mode", "opa_policy_violation")),
            )
        if result.status == VerificationStatus.PASS:
            return HumanExplanation(summary="OPA reported no self-protection violations.", repair_hint="No repair required.")
        return HumanExplanation(
            summary=f"OPA-native backend returned {result.status.value}.",
            repair_hint="Install opa or select an explicitly accepted fallback backend via policy.",
            failure_mode=result.status.value,
        )


ADAPTER = OpaNativeSelfProtectionAdapter()
