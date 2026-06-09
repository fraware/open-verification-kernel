"""Evidence construction for infrastructure exposure checks."""

from __future__ import annotations

from typing import Any

from ovk.adapters.infra.exposure import find_exposure_counterexamples
from ovk.adapters.infra.validation import issues_to_diagnostics, validate_infra_input
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


INTENT_ID = "no-public-sensitive-resource"
INTENT_TITLE = "No public exposure of sensitive infrastructure resources"


def evaluate_infra_exposure(
    data: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> VerificationEvidence:
    """Evaluate infrastructure exposure and return OVK evidence."""
    subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
    if base_sha is not None:
        subject["base_sha"] = base_sha

    issues = validate_infra_input(data)
    if issues:
        status = VerificationStatus.UNKNOWN
        recommendation = "require_human_review"
        counterexamples = issues_to_diagnostics(issues)
    else:
        counterexamples = find_exposure_counterexamples(data)
        status = VerificationStatus.FAIL if counterexamples else VerificationStatus.PASS
        recommendation = "block" if counterexamples else "allow"

    return VerificationEvidence(
        evidence_id="ev-infra-exposure",
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
                backend="infra",
                guarantee_type="exposure_graph_check",
                status=status,
                assumptions=[
                    "Infrastructure exposure abstraction is supplied by the input.",
                    "Confidential and restricted resources must not be publicly exposed.",
                ],
                limits=[
                    "The checker does not parse Terraform or Kubernetes files directly yet.",
                    "Invalid infrastructure abstractions require human review.",
                ],
                adapter_version="0.1.0",
            )
        ],
        counterexamples=counterexamples,
        generated_artifacts=[],
        decision={
            "merge_recommendation": recommendation,
            "human_review_required": recommendation != "allow",
            "override_allowed": recommendation != "allow",
            "override_requires": ["maintainer", "security-review"] if recommendation != "allow" else [],
        },
    )
