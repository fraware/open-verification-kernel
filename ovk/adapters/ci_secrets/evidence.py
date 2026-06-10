"""Evidence construction for CI secrets exposure checks."""

from __future__ import annotations

from typing import Any

from ovk.adapters.ci_secrets.exposure import find_ci_secrets_counterexamples
from ovk.adapters.ci_secrets.regression import render_ci_secrets_regression_suite
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


INTENT_ID = "no-secrets-in-untrusted-context"
INTENT_TITLE = "No secrets exposed to untrusted CI contexts"


def evaluate_ci_secrets_exposure(
    data: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> VerificationEvidence:
    """Evaluate CI secrets exposure and return OVK evidence."""
    subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
    if base_sha is not None:
        subject["base_sha"] = base_sha

    workflows = data.get("workflows")
    if not isinstance(workflows, list) or not workflows:
        status = VerificationStatus.UNKNOWN
        recommendation = "require_human_review"
        counterexamples = [
            {
                "summary": "Workflow abstraction is missing or empty.",
                "failure_mode": "missing_workflow_abstraction",
            }
        ]
    else:
        counterexamples = find_ci_secrets_counterexamples(data)
        status = VerificationStatus.FAIL if counterexamples else VerificationStatus.PASS
        recommendation = "block" if counterexamples else "allow"

    generated_artifacts: list[dict[str, Any]] = []
    if counterexamples and status == VerificationStatus.FAIL:
        generated_artifacts.append(
            {
                "kind": "regression_unit_test",
                "path": ".verification/generated_tests/test_no_secrets_in_untrusted_context.py",
                "content": render_ci_secrets_regression_suite(counterexamples),
            }
        )

    return VerificationEvidence(
        evidence_id="ev-ci-secrets",
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
            "risk": {"severity": "critical"},
        },
        backend_claims=[
            BackendClaim(
                backend="ci_secrets",
                guarantee_type="workflow_secrets_boundary_check",
                status=status,
                assumptions=[
                    "Workflow abstraction is supplied by the input.",
                    "Untrusted fork pull-request contexts must not receive secret references.",
                ],
                limits=[
                    "The checker uses normalized workflow abstractions, not full YAML parsing.",
                    "Missing workflow metadata requires human review.",
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
