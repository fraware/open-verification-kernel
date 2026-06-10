"""Shared deterministic-fallback evaluator for external backends."""

from __future__ import annotations

import shutil
from typing import Any, Callable

from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


def evaluate_with_optional_binary(
    *,
    backend_name: str,
    binary_name: str,
    data: dict[str, Any],
    repo: str,
    head_sha: str,
    base_sha: str | None,
    deterministic_evaluator: Callable[[dict[str, Any]], tuple[str, list[dict[str, Any]]]],
    assumptions: list[str],
    limits: list[str],
) -> VerificationEvidence:
    """Run deterministic oracle; annotate when the native binary is unavailable."""
    binary_available = shutil.which(binary_name) is not None
    status_raw, counterexamples = deterministic_evaluator(data)
    status = VerificationStatus(status_raw)
    claim_assumptions = list(assumptions)
    claim_assumptions.append(f"{backend_name} adapter uses deterministic fallback when binary is absent.")
    if not binary_available:
        claim_assumptions.append(f"{binary_name} binary unavailable; deterministic oracle result used.")
    merge_by_status = {
        VerificationStatus.PASS: "allow",
        VerificationStatus.FAIL: "block",
        VerificationStatus.UNKNOWN: "require_human_review",
        VerificationStatus.ERROR: "require_human_review",
        VerificationStatus.SKIPPED: "require_human_review",
    }
    recommendation = merge_by_status.get(status, "require_human_review")
    intent_id = str(data.get("intent_id", backend_name))
    subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
    if base_sha is not None:
        subject["base_sha"] = base_sha
    return VerificationEvidence(
        evidence_id=f"{backend_name}-{head_sha[:8]}",
        subject=subject,
        intent={
            "intent_id": intent_id,
            "title": intent_id.replace("-", " ").title(),
            "risk": {"severity": "medium"},
        },
        backend_claims=[
            BackendClaim(
                backend=backend_name,
                guarantee_type="deterministic_fallback" if not binary_available else "native_tool",
                status=status,
                assumptions=claim_assumptions,
                limits=limits,
                adapter_version="0.1.0",
            )
        ],
        counterexamples=counterexamples,
        decision={"merge_recommendation": recommendation},
    )
