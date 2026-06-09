"""Evidence construction for authorization obligation results."""

from __future__ import annotations

from typing import Any

from ovk.adapters.z3.obligation import AuthorizationObligation, obligation_to_dict
from ovk.adapters.z3.regression import render_authorization_regression_suite
from ovk.adapters.z3.result import normalize_z3_authorization_result, recommendation_from_z3_status
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


STATUS_MAP = {
    "pass": VerificationStatus.PASS,
    "fail": VerificationStatus.FAIL,
    "unknown": VerificationStatus.UNKNOWN,
    "error": VerificationStatus.ERROR,
}


def authorization_result_to_evidence(
    raw: dict[str, Any],
    obligation: AuthorizationObligation,
    *,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
    author_type: str = "unknown",
    agent: str = "unknown",
    task: str = "unknown",
) -> VerificationEvidence:
    """Create OVK evidence from a normalized authorization obligation result."""
    normalized = normalize_z3_authorization_result(raw)
    status_text = str(normalized["status"])
    status = STATUS_MAP.get(status_text, VerificationStatus.UNKNOWN)
    recommendation = recommendation_from_z3_status(status_text)
    counterexamples = normalized["counterexamples"]

    subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
    if base_sha is not None:
        subject["base_sha"] = base_sha

    generated_artifacts: list[dict[str, Any]] = [
        {
            "kind": "authorization_obligation",
            "obligation": obligation_to_dict(obligation),
        }
    ]
    if counterexamples:
        generated_artifacts.append(
            {
                "kind": "regression_unit_test",
                "path": ".verification/generated_tests/test_no_admin_route_bypass.py",
                "content": render_authorization_regression_suite(counterexamples),
            }
        )

    return VerificationEvidence(
        evidence_id="ev-auth-obligation-z3",
        schema_version="ovk.evidence.v1",
        subject=subject,
        change_origin={
            "author_type": author_type,
            "agent": agent,
            "task": task,
        },
        intent={
            "intent_id": obligation.intent_id,
            "title": "No admin route bypass",
            "risk": {"severity": "high"},
        },
        backend_claims=[
            BackendClaim(
                backend="z3",
                guarantee_type="smt_reachability_obligation",
                status=status,
                assumptions=obligation.assumptions,
                limits=[
                    "The obligation is built from a supplied route-reachability abstraction.",
                    "Unknown solver outcomes require human review.",
                ],
                adapter_version="0.3.0",
            )
        ],
        counterexamples=counterexamples,
        generated_artifacts=generated_artifacts,
        decision={
            "merge_recommendation": recommendation,
            "human_review_required": recommendation != "allow",
            "override_allowed": recommendation != "allow",
            "override_requires": ["maintainer", "security-review"] if recommendation != "allow" else [],
        },
    )
