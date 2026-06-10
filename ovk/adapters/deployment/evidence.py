"""Evidence construction for approval state machine checks."""

from __future__ import annotations

from typing import Any

from ovk.adapters.deployment.regression import render_deployment_regression_suite
from ovk.adapters.deployment.state_machine import find_skipped_approval_paths
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


INTENT_ID = "no-skipped-approval-state"
INTENT_TITLE = "Deployment changes cannot skip required approval states"


def evaluate_approval_state_machine(
    data: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> VerificationEvidence:
    """Evaluate approval state machine and return OVK evidence."""
    subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
    if base_sha is not None:
        subject["base_sha"] = base_sha

    if not data.get("states") or not data.get("transitions"):
        status = VerificationStatus.UNKNOWN
        recommendation = "require_human_review"
        counterexamples = [
            {
                "summary": "State machine abstraction is missing states or transitions.",
                "failure_mode": "missing_state_machine_abstraction",
            }
        ]
    else:
        counterexamples = find_skipped_approval_paths(data)
        status = VerificationStatus.FAIL if counterexamples else VerificationStatus.PASS
        recommendation = "block" if counterexamples else "allow"

    generated_artifacts: list[dict[str, Any]] = []
    if counterexamples and status == VerificationStatus.FAIL:
        generated_artifacts.append(
            {
                "kind": "regression_unit_test",
                "path": ".verification/generated_tests/test_no_skipped_approval_state.py",
                "content": render_deployment_regression_suite(counterexamples),
            }
        )

    return VerificationEvidence(
        evidence_id="ev-approval-state",
        schema_version="ovk.evidence.v1",
        subject=subject,
        change_origin={
            "author_type": data.get("author_type", "unknown"),
            "agent": data.get("agent", "unknown"),
            "task": data.get("task", "unknown"),
        },
        intent={
            "intent_id": INTENT_ID,
            "title": INTENT_TITLE,
            "risk": {"severity": "high"},
        },
        backend_claims=[
            BackendClaim(
                backend="deployment_state",
                guarantee_type="approval_state_reachability_check",
                status=status,
                assumptions=[
                    "Deployment state machine abstraction is supplied by the input.",
                    "Required approval states must appear on every production path.",
                ],
                limits=[
                    "The checker uses normalized state-machine abstractions.",
                    "Invalid abstractions require human review.",
                ],
                adapter_version="0.1.0",
            )
        ],
        decision={
            "merge_recommendation": recommendation,
            "human_review_required": recommendation != "allow",
        },
        counterexamples=counterexamples,
        generated_artifacts=generated_artifacts,
    )
