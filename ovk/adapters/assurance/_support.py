"""Shared helpers for assurance-only BackendAdapter implementations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from ovk.assurance.indeterminate import (
    DECISION_ACCEPT,
    DECISION_REJECT,
    indeterminate_outcome,
)
from ovk.assurance.pcs_hash import sha256_digest
from ovk.core.execution_models import (
    AbstractionCoverage,
    BackendCapabilityAssessment,
    BackendEnvironmentFingerprint,
    BackendObligation,
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
from ovk.core.models import VerificationStatus


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def accept_outcome(
    *,
    raw_result: Mapping[str, Any],
    normalized_extra: Mapping[str, Any] | None = None,
    stdout: str = "accept",
    stderr: str = "",
    guarantee_class: str,
    command_argv: list[str],
    exit_code: int = 0,
) -> dict[str, Any]:
    normalized: dict[str, Any] = {
        "decision": DECISION_ACCEPT,
        "guarantee_class": guarantee_class,
        "status": "pass",
    }
    if normalized_extra:
        normalized.update(dict(normalized_extra))
    return {
        "exit_kind": "exited",
        "exit_code": exit_code,
        "status": "pass",
        "decision": DECISION_ACCEPT,
        "execution_status": "completed",
        "indeterminate_reason": None,
        "stdout": stdout,
        "stderr": stderr,
        "raw_result": dict(raw_result),
        "normalized_result": normalized,
        "guarantee_class": guarantee_class,
        "command_argv": list(command_argv),
    }


def reject_outcome(
    *,
    raw_result: Mapping[str, Any],
    normalized_extra: Mapping[str, Any] | None = None,
    stdout: str = "reject",
    stderr: str = "",
    guarantee_class: str,
    command_argv: list[str],
    exit_code: int = 1,
) -> dict[str, Any]:
    normalized: dict[str, Any] = {
        "decision": DECISION_REJECT,
        "guarantee_class": guarantee_class,
        "status": "fail",
    }
    if normalized_extra:
        normalized.update(dict(normalized_extra))
    return {
        "exit_kind": "exited",
        "exit_code": exit_code,
        "status": "fail",
        "decision": DECISION_REJECT,
        "execution_status": "completed",
        "indeterminate_reason": None,
        "stdout": stdout,
        "stderr": stderr,
        "raw_result": dict(raw_result),
        "normalized_result": normalized,
        "guarantee_class": guarantee_class,
        "command_argv": list(command_argv),
    }


def indeterminate_run_outcome(
    *,
    reason: str,
    message: str,
    raw_result: Mapping[str, Any] | None = None,
    guarantee_class: str,
    command_argv: list[str],
    exit_code: int | None = 2,
    exit_kind: str = "exited",
) -> dict[str, Any]:
    ind = indeterminate_outcome(reason=reason, message=message)
    normalized = {
        "decision": ind["decision"],
        "guarantee_class": guarantee_class,
        "status": "unknown",
        "indeterminate_reason": ind["indeterminate_reason"],
    }
    return {
        "exit_kind": exit_kind,
        "exit_code": exit_code,
        "status": "unknown",
        "decision": ind["decision"],
        "execution_status": ind["execution_status"],
        "indeterminate_reason": ind["indeterminate_reason"],
        "stdout": "",
        "stderr": message,
        "raw_result": dict(raw_result or {"error": reason, "message": message}),
        "normalized_result": normalized,
        "guarantee_class": guarantee_class,
        "command_argv": list(command_argv),
        "message": message,
    }


class AssuranceBackendMixin:
    """Minimal BackendAdapter surface so assurance adapters can register.

    Ordinary ``ovk check`` routing does not select these backends; they exist
    for ``ovk verifier`` and the assurance registry only.
    """

    backend_id: str
    adapter_id: str
    adapter_version: str
    _guarantee_type: str = "exact_predicate"
    _domain: str = "assurance"

    def can_handle(
        self,
        obligation: VerificationObligation,
        context: ExecutionContext,
    ) -> BackendCapabilityAssessment:
        return BackendCapabilityAssessment(
            backend=self.backend_id,
            support="unsupported",
            score=0.0,
            guarantee_type=self._guarantee_type,
            material_requirements_met=False,
            coverage_requirements_met=False,
            native_available=True,
            estimated_wall_time_seconds=1.0,
            estimated_memory_mb=128,
            reasons=["assurance-only backend; not selected by ordinary routing"],
        )

    def compile(
        self,
        obligation: VerificationObligation,
        routing: RoutingDecision,
    ) -> BackendObligation:
        payload = {"abstraction": obligation.abstraction, "mode": "assurance"}
        provisional = BackendObligation(
            backend_obligation_id="pending",
            obligation_id=obligation.obligation_id,
            routing_id=routing.routing_id,
            backend=self.backend_id,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            input_language="json",
            payload=payload,
            payload_digest=compute_payload_digest(payload),
            required=False,
            timeout_seconds=30.0,
            memory_mb=256,
        )
        return provisional.model_copy(
            update={"backend_obligation_id": compute_backend_obligation_id(provisional)}
        )

    def fingerprint(self, backend_obligation: BackendObligation) -> BackendEnvironmentFingerprint:
        return BackendEnvironmentFingerprint(
            backend=self.backend_id,
            adapter_version=self.adapter_version,
            environment_digest=sha256_digest({"backend": self.backend_id})[7:],
            native_available=True,
        )

    def run(
        self,
        backend_obligation: BackendObligation,
        budget: ExecutionBudget,
    ) -> RawBackendExecution:
        started = utc_now_iso()
        return RawBackendExecution(
            backend=self.backend_id,
            termination="cancelled",
            native_execution=False,
            raw_result={"error": "assurance backends are not invoked via ordinary run()"},
            stdout="",
            stderr="use ovk verifier run / run_assurance()",
            exit_code=None,
            started_at=started,
            finished_at=utc_now_iso(),
        )

    def normalize(
        self,
        raw: RawBackendExecution,
        backend_obligation: BackendObligation,
    ) -> NormalizedBackendResult:
        return NormalizedBackendResult(
            attempt_id=f"{self.backend_id}-ordinary-unused",
            backend=self.backend_id,
            status=VerificationStatus.UNKNOWN,
            guarantee_type=self._guarantee_type,
            assumptions=["assurance-only; ordinary normalize is unused"],
            limits=["cannot upgrade guarantee class via ordinary normalize"],
        )

    def explain(self, result: NormalizedBackendResult) -> HumanExplanation:
        return HumanExplanation(
            summary=f"{self.backend_id} ordinary path unused (assurance-only)",
            repair_hint="Use ovk verifier run with an assurance evidence pack.",
            failure_mode=None,
        )


# Keep coverage type importable for obligation construction in tests.
_ = AbstractionCoverage
