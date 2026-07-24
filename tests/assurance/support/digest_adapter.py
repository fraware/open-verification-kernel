"""Real deterministic test-only assurance adapter (NOT production-registered).

Exact predicate: an input field equals an expected digest, or a boolean
predicate over JSON. Implements snapshot_config, run_assurance, normalize
semantics, and mutations alter_timeout + change_threshold.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from ovk.assurance.indeterminate import (
    DECISION_ACCEPT,
    DECISION_REJECT,
    indeterminate_outcome,
)
from ovk.assurance.pcs_hash import sha256_digest
from ovk.assurance.snapshot import ConfigurationSnapshot, build_configuration_snapshot
from ovk.core.execution_models import (
    AbstractionCoverage,
    AssuranceAbstention,
    AssuranceCapabilitySection,
    AssuranceDecisionSemantics,
    AssuranceFailureBehavior,
    AssuranceReplaySupport,
    AssuranceSnapshotSupport,
    AssuranceVerifierIdentity,
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
from ovk.core.models import VerificationStatus


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DigestPredicateAdapter:
    """Deterministic digest/boolean predicate checker for assurance tests only."""

    backend_id = "test-digest-predicate"
    adapter_id = "ovk-adapter-test-digest-predicate"
    adapter_version = "0.1.0"

    def __init__(
        self,
        *,
        expected_digest: str | None = None,
        field: str = "digest",
        predicate_field: str = "ok",
        mode: str = "digest",
        missing_checker: bool = False,
        force_timeout: bool = False,
        threshold: int = 1,
        timeout_ms: int = 5_000,
    ) -> None:
        self.expected_digest = expected_digest
        self.field = field
        self.predicate_field = predicate_field
        self.mode = mode  # "digest" | "boolean"
        self.missing_checker = missing_checker
        self.force_timeout = force_timeout
        self.threshold = threshold
        self.timeout_ms = timeout_ms

    def manifest(self) -> BackendCapabilityManifest:
        return BackendCapabilityManifest(
            capability_id="test-digest-predicate-v1",
            tool=BackendToolIdentity(
                name=self.backend_id,
                adapter=self.adapter_id,
                adapter_version=self.adapter_version,
                version=self.adapter_version,
            ),
            backend_class="custom",
            guarantee=BackendGuaranteeDeclaration(
                type="exact_predicate",
                meaning_of_pass="Input satisfies the configured exact predicate.",
                meaning_of_fail="Input violates the configured exact predicate.",
                meaning_of_unknown="Checker missing, timed out, or input unsupported.",
            ),
            input_languages=["json"],
            supported_domains=["assurance_test"],
            supported_property_kinds=["exact_predicate"],
            assumptions=["Test-only adapter; not for production assurance claims."],
            limits=["Evaluates a single field predicate only."],
            result_format="ovk.result.v1",
            timeout_behavior="unknown",
            assurance=AssuranceCapabilitySection(
                assurance_capable=True,
                verifier_identity=AssuranceVerifierIdentity(
                    verifier_id="ovk.test.digest_predicate",
                    implementation_name="DigestPredicateAdapter",
                    entry_point="tests.assurance.support.digest_adapter.DigestPredicateAdapter",
                    pcs_profile_artifact_type="VerifierProfile.v1",
                ),
                decision_semantics=AssuranceDecisionSemantics(
                    decision_space=[
                        "accept",
                        "reject",
                        "indeterminate_execution_error",
                        "indeterminate_out_of_scope",
                    ],
                    guarantee_class="observational",
                    supported_claim_ids=["claim.test.digest_predicate"],
                    out_of_scope_claim_ids=["claim.formal.full_correctness"],
                ),
                mechanism_class="static_analysis",
                determinism="deterministic",
                evidence_channels=["raw_backend_result", "normalized_result", "compiled_obligation"],
                replay_support=AssuranceReplaySupport(
                    supported=True,
                    compares_raw_digest=True,
                    compares_normalized_digest=True,
                ),
                configuration_snapshot_support=AssuranceSnapshotSupport(
                    supported=True,
                    exports_pcs_profile=True,
                ),
                mutation_dimensions=["alter_timeout", "change_threshold"],
                abstention=AssuranceAbstention(allows_abstention=True),
                failure_behavior=AssuranceFailureBehavior(),
                external_dependencies=[],
                known_limits=["test-only exact predicate"],
            ),
        )

    def supported_mutation_dimensions(self) -> list[str]:
        return ["alter_timeout", "change_threshold"]

    def snapshot_config(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> ConfigurationSnapshot:
        cfg = dict(config or {})
        cfg.setdefault("timeout_ms", self.timeout_ms)
        cfg.setdefault("threshold", self.threshold)
        cfg.setdefault("mode", self.mode)
        cfg.setdefault("field", self.field)
        if self.expected_digest is not None:
            cfg.setdefault("expected_digest", self.expected_digest)
        return build_configuration_snapshot(
            backend_id=self.backend_id,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            config=cfg,
            environment=environment,
            mechanism_class="static_analysis",
            determinism="deterministic",
            allows_abstention=True,
            guarantee_class="observational",
            decision_space=[
                "accept",
                "reject",
                "indeterminate_execution_error",
                "indeterminate_out_of_scope",
            ],
            supported_claim_ids=["claim.test.digest_predicate"],
            out_of_scope_claim_ids=["claim.formal.full_correctness"],
            assumptions=["Test-only adapter"],
            known_blind_spots=["single-field predicate"],
            entry_point="tests.assurance.support.digest_adapter.DigestPredicateAdapter",
            implementation_name="DigestPredicateAdapter",
            timeout_ms=int(cfg["timeout_ms"]),
            mutation_dimensions=self.supported_mutation_dimensions(),
            threshold=cfg.get("threshold"),
        )

    def run_assurance(
        self,
        *,
        input_data: Mapping[str, Any],
        snapshot: ConfigurationSnapshot,
        config: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.missing_checker:
            raise FileNotFoundError("digest-predicate-checker binary not found")
        if self.force_timeout:
            raise TimeoutError("digest-predicate-checker timed out")

        cfg = dict(snapshot.config)
        if config:
            cfg.update(dict(config))
        threshold = int(cfg.get("threshold", self.threshold))
        mode = str(cfg.get("mode", self.mode))
        field = str(cfg.get("field", self.field))

        raw: dict[str, Any] = {
            "mode": mode,
            "field": field,
            "threshold": threshold,
            "input": dict(input_data),
        }

        if mode == "boolean":
            value = input_data.get(self.predicate_field)
            if not isinstance(value, bool):
                ind = indeterminate_outcome(reason="unsupported_input", message="boolean field missing")
                normalized = {
                    "decision": ind["decision"],
                    "guarantee_class": "observational",
                    "status": "unknown",
                }
                return {
                    "exit_kind": "exited",
                    "exit_code": 2,
                    "status": "unknown",
                    "decision": ind["decision"],
                    "execution_status": ind["execution_status"],
                    "indeterminate_reason": ind["indeterminate_reason"],
                    "stdout": "",
                    "stderr": ind["message"],
                    "raw_result": raw,
                    "normalized_result": normalized,
                    "guarantee_class": "observational",
                    "command_argv": [self.adapter_id, "boolean-predicate"],
                }
            passed = value is True and threshold >= 1
        else:
            expected = cfg.get("expected_digest", self.expected_digest)
            actual = input_data.get(field)
            raw["expected_digest"] = expected
            raw["actual"] = actual
            if not isinstance(expected, str) or not isinstance(actual, str):
                ind = indeterminate_outcome(reason="unsupported_input", message="digest field missing")
                normalized = {
                    "decision": ind["decision"],
                    "guarantee_class": "observational",
                    "status": "unknown",
                }
                return {
                    "exit_kind": "exited",
                    "exit_code": 2,
                    "status": "unknown",
                    "decision": ind["decision"],
                    "execution_status": ind["execution_status"],
                    "indeterminate_reason": ind["indeterminate_reason"],
                    "stdout": "",
                    "stderr": ind["message"],
                    "raw_result": raw,
                    "normalized_result": normalized,
                    "guarantee_class": "observational",
                    "command_argv": [self.adapter_id, "digest-predicate"],
                }
            passed = actual == expected and threshold >= 1

        decision = DECISION_ACCEPT if passed else DECISION_REJECT
        raw["passed"] = passed
        normalized = {
            "decision": decision,
            "guarantee_class": "observational",
            "status": "pass" if passed else "fail",
            "predicate_digest": sha256_digest({"mode": mode, "field": field, "threshold": threshold}),
        }
        return {
            "exit_kind": "exited",
            "exit_code": 0 if passed else 1,
            "status": "pass" if passed else "fail",
            "decision": decision,
            "execution_status": "completed",
            "indeterminate_reason": None,
            "stdout": "pass" if passed else "fail",
            "stderr": "",
            "raw_result": raw,
            "normalized_result": normalized,
            "guarantee_class": "observational",
            "command_argv": [self.adapter_id, f"{mode}-predicate"],
        }

    # --- BackendAdapter surface (required for temporary registry registration) ---

    def can_handle(
        self,
        obligation: VerificationObligation,
        context: ExecutionContext,
    ) -> BackendCapabilityAssessment:
        return BackendCapabilityAssessment(
            backend=self.backend_id,
            support="supported",
            score=1.0,
            guarantee_type="exact_predicate",
            material_requirements_met=True,
            coverage_requirements_met=True,
            native_available=True,
            estimated_wall_time_seconds=0.1,
            estimated_memory_mb=64,
            reasons=["test digest predicate"],
        )

    def compile(
        self,
        obligation: VerificationObligation,
        routing: RoutingDecision,
    ) -> BackendObligation:
        payload = {"abstraction": obligation.abstraction}
        provisional = BackendObligation(
            backend_obligation_id="pending",
            obligation_id=obligation.obligation_id,
            backend=self.backend_id,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            input_language="json",
            payload=payload,
            payload_digest=compute_payload_digest(payload),
            required=True,
            timeout_seconds=5.0,
            memory_mb=64,
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
        started = _utc_now_iso()
        snap = self.snapshot_config({"timeout_ms": self.timeout_ms, "threshold": self.threshold})
        outcome = self.run_assurance(
            input_data=dict(backend_obligation.payload.get("abstraction") or {}),
            snapshot=snap,
        )
        return RawBackendExecution(
            backend=self.backend_id,
            termination="completed",
            native_execution=True,
            raw_result=dict(outcome.get("raw_result") or {}),
            stdout=str(outcome.get("stdout") or ""),
            stderr=str(outcome.get("stderr") or ""),
            exit_code=outcome.get("exit_code"),
            started_at=started,
            finished_at=_utc_now_iso(),
        )

    def normalize(
        self,
        raw: RawBackendExecution,
        backend_obligation: BackendObligation,
    ) -> NormalizedBackendResult:
        status_raw = str((raw.raw_result or {}).get("passed"))
        if status_raw == "True":
            status = VerificationStatus.PASS
        elif status_raw == "False":
            status = VerificationStatus.FAIL
        else:
            status = VerificationStatus.UNKNOWN
        # Never upgrade guarantee class beyond observational.
        return NormalizedBackendResult(
            attempt_id="test-digest",
            backend=self.backend_id,
            status=status,
            guarantee_type="exact_predicate",
            assumptions=["observational exact predicate"],
            limits=["cannot upgrade to formally_checked"],
        )

    def explain(self, result: NormalizedBackendResult) -> HumanExplanation:
        return HumanExplanation(
            summary=f"digest predicate status={result.status}",
            repair_hint="Adjust input digest or boolean predicate.",
            failure_mode=None,
        )


# Silence unused import for AbstractionCoverage if needed by callers constructing obligations.
_ = AbstractionCoverage
