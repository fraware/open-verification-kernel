"""Base implementation for external backend adapters."""

from __future__ import annotations

from typing import Any, Callable

from ovk.adapters.contract import (
    CapabilityScore,
    HumanExplanation,
    ProofObligation,
    RawBackendResult,
    VerificationResult,
)
from ovk.adapters.external.stub import evaluate_with_optional_binary
from ovk.core.models import VerificationEvidence


class BaseExternalAdapter:
    """Reusable adapter skeleton with deterministic fallback."""

    backend_name: str
    binary_name: str
    capability_manifest: dict[str, Any]
    input_language: str
    adapter_version: str = "0.1.0"

    def manifest(self) -> dict[str, Any]:
        return self.capability_manifest

    def can_handle(self, *, intent: dict[str, Any], context: dict[str, Any]) -> CapabilityScore:
        domain = intent.get("domain")
        property_kind = intent.get("property", {}).get("kind")
        domains = set(self.capability_manifest.get("supported_domains", []))
        kinds = set(self.capability_manifest.get("supported_property_kinds", []))
        if domain in domains and property_kind in kinds:
            bonus = float(context.get("surface_bonus", 0.0))
            return CapabilityScore(
                backend=self.backend_name,
                score=0.85 + bonus,
                reason=f"supports {domain}/{property_kind}",
            )
        if domain in domains:
            return CapabilityScore(backend=self.backend_name, score=0.35, reason=f"supports domain {domain}")
        return CapabilityScore(backend=self.backend_name, score=0.0, reason=f"does not support domain {domain}")

    def compile(self, *, intent: dict[str, Any], change: dict[str, Any]) -> ProofObligation:
        return ProofObligation(
            backend=self.backend_name,
            intent_id=str(intent.get("intent_id", "unknown")),
            input=dict(change.get("input", {})),
            input_language=self.input_language,
            scope=[str(path) for path in change.get("changed_files", [])],
        )

    def run(self, obligation: ProofObligation) -> RawBackendResult:
        evaluator = self._deterministic_evaluator()
        status, counterexamples = evaluator(obligation.input)
        import shutil

        return RawBackendResult(
            backend=self.backend_name,
            status=status,
            counterexamples=counterexamples,
            used_native_binary=shutil.which(self.binary_name) is not None,
        )

    def normalize(self, raw: RawBackendResult, obligation: ProofObligation) -> VerificationResult:
        status = raw.status
        merge_by_status = {
            "pass": "allow",
            "fail": "block",
            "unknown": "require_human_review",
            "error": "require_human_review",
            "skipped": "require_human_review",
        }
        assumptions = [f"{self.backend_name} adapter uses deterministic fallback when binary is absent."]
        if not raw.used_native_binary:
            assumptions.append(f"{self.binary_name} binary unavailable; deterministic oracle result used.")
        return VerificationResult(
            status=status,
            merge_recommendation=merge_by_status.get(status, "require_human_review"),
            counterexamples=raw.counterexamples,
            assumptions=assumptions,
            limits=list(self.capability_manifest.get("limits", [])),
        )

    def explain(self, result: VerificationResult) -> HumanExplanation:
        if result.counterexamples:
            counterexample = result.counterexamples[0]
            return HumanExplanation(
                summary=str(counterexample.get("summary", "Verification failed.")),
                repair_hint="Review the reported violation and apply a targeted fix.",
                failure_mode=str(counterexample.get("failure_mode")),
            )
        return HumanExplanation(
            summary="Verification passed under the stated assumptions and bounds.",
            repair_hint="No repair required.",
        )

    def evaluate_evidence(
        self,
        data: dict[str, Any],
        *,
        repo: str,
        head_sha: str,
        base_sha: str | None = None,
    ) -> VerificationEvidence:
        """Produce OVK evidence from adapter input data."""
        return evaluate_with_optional_binary(
            backend_name=self.backend_name,
            binary_name=self.binary_name,
            data={**data, "intent_id": data.get("intent_id", self.backend_name)},
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            deterministic_evaluator=self._deterministic_evaluator(),
            assumptions=[f"{self.backend_name} adapter contract evaluation."],
            limits=list(self.capability_manifest.get("limits", [])),
        )

    def _deterministic_evaluator(self) -> Callable[[dict[str, Any]], tuple[str, list[dict[str, Any]]]]:
        raise NotImplementedError
