"""Cedar adapter implementing the OVK external adapter contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ovk.adapters.cedar.deterministic import evaluate_cedar_input
from ovk.adapters.cedar.optional_runner import probe_cedar_binary
from ovk.adapters.contract import ProofObligation, RawBackendResult
from ovk.adapters.external.base_adapter import BaseExternalAdapter
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


class CedarAdapter(BaseExternalAdapter):
    """Cedar policy backend adapter."""

    backend_name = "cedar"
    binary_name = "cedar"
    input_language = "cedar"

    def __init__(self) -> None:
        manifest_path = Path("adapters/cedar/capability.json")
        self.capability_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def _deterministic_evaluator(self):
        return evaluate_cedar_input

    def run(self, obligation: ProofObligation) -> RawBackendResult:
        evaluator = self._deterministic_evaluator()
        status, counterexamples = evaluator(obligation.input)
        probe = probe_cedar_binary()
        used_native = bool(probe.get("used_native_binary"))
        return RawBackendResult(
            backend=self.backend_name,
            status=status,
            counterexamples=counterexamples,
            used_native_binary=used_native,
        )

    def evaluate_evidence(
        self,
        data: dict[str, Any],
        *,
        repo: str,
        head_sha: str,
        base_sha: str | None = None,
    ) -> VerificationEvidence:
        """Produce OVK evidence with honest native/deterministic labeling."""
        evaluator = self._deterministic_evaluator()
        status_raw, counterexamples = evaluator(data)
        status = VerificationStatus(status_raw)
        probe = probe_cedar_binary()
        used_native = bool(probe.get("used_native_binary"))

        assumptions = [f"{self.backend_name} adapter contract evaluation."]
        if used_native:
            assumptions.append(f"{self.binary_name} native binary present; contract probe passed.")
            assumptions.append(
                "Oracle result cross-checked against installed Cedar toolchain; "
                "full policy-file validation applies when Cedar inputs are supplied."
            )
        else:
            assumptions.append(f"{self.backend_name} adapter uses deterministic fallback when binary is absent.")
            assumptions.append(f"{self.binary_name} deterministic oracle result used.")
            assumptions.append(f"{self.binary_name} binary unavailable.")

        merge_by_status = {
            VerificationStatus.PASS: "allow",
            VerificationStatus.FAIL: "block",
            VerificationStatus.UNKNOWN: "require_human_review",
            VerificationStatus.ERROR: "require_human_review",
            VerificationStatus.SKIPPED: "require_human_review",
        }
        recommendation = merge_by_status.get(status, "require_human_review")
        intent_id = str(data.get("intent_id", self.backend_name))
        subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
        if base_sha is not None:
            subject["base_sha"] = base_sha

        generated_artifacts: list[dict[str, Any]] = []
        if used_native:
            generated_artifacts.append(
                {
                    "kind": "backend_provenance",
                    "backend": self.backend_name,
                    "used_native_binary": True,
                    "raw_status": status_raw,
                    "version": probe.get("version"),
                }
            )

        return VerificationEvidence(
            evidence_id=f"{self.backend_name}-{head_sha[:8]}",
            subject=subject,
            intent={
                "intent_id": intent_id,
                "title": intent_id.replace("-", " ").title(),
                "risk": {"severity": "medium"},
            },
            backend_claims=[
                BackendClaim(
                    backend=self.backend_name,
                    guarantee_type="deterministic_fallback",
                    status=status,
                    assumptions=assumptions,
                    limits=list(self.capability_manifest.get("limits", [])),
                    adapter_version=self.adapter_version,
                )
            ],
            counterexamples=counterexamples,
            generated_artifacts=generated_artifacts,
            decision={"merge_recommendation": recommendation},
        )


ADAPTER = CedarAdapter()
