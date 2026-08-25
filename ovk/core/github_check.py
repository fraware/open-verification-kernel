"""GitHub check-run helpers for OVK merge recommendations."""

from __future__ import annotations

from typing import Any

from ovk.core.decision import merge_recommendation_to_decision_state
from ovk.core.models import DecisionState, EvidenceBundle


CHECK_NAME = "Open Verification Kernel"

CONCLUSION_BY_DECISION_STATE = {
    DecisionState.ALLOW.value: "success",
    DecisionState.BLOCK.value: "failure",
    DecisionState.NEEDS_REVIEW.value: "neutral",
    DecisionState.UNKNOWN.value: "neutral",
    DecisionState.ERROR.value: "neutral",
    DecisionState.SKIPPED.value: "neutral",
}

# Deprecated merge_recommendation aliases.
CONCLUSION_BY_RECOMMENDATION = {
    "allow": "success",
    "block": "failure",
    "require_human_review": "neutral",
    "allow_with_warning": "success",
    "require_stronger_check": "neutral",
    "needs_review": "neutral",
    "unknown": "neutral",
    "error": "neutral",
    "skipped": "neutral",
}


class StaleCheckRunError(ValueError):
    """Raised when a check run would be published against a mismatched head SHA."""


def check_run_external_id(*, repo: str, head_sha: str) -> str:
    """Stable external_id for idempotent check-run create/update by head SHA."""
    return f"ovk:{repo}:{head_sha}"


def _decision_state_from_bundle(bundle: EvidenceBundle) -> str:
    decision = bundle.decision or {}
    if decision.get("decision_state"):
        return str(decision["decision_state"])
    recommendation = str(decision.get("merge_recommendation", "require_human_review"))
    return merge_recommendation_to_decision_state(recommendation).value


def check_conclusion_for_recommendation(recommendation: str) -> str:
    """Map an OVK decision_state or merge recommendation to a GitHub check conclusion."""
    if recommendation in CONCLUSION_BY_DECISION_STATE:
        return CONCLUSION_BY_DECISION_STATE[recommendation]
    if recommendation in CONCLUSION_BY_RECOMMENDATION:
        return CONCLUSION_BY_RECOMMENDATION[recommendation]
    state = merge_recommendation_to_decision_state(recommendation)
    return CONCLUSION_BY_DECISION_STATE.get(state.value, "neutral")


def validate_check_run_head_sha(bundle: EvidenceBundle, head_sha: str) -> None:
    """Fail closed when evidence subject SHA does not match the emit target.

    Stale check results must never authorize a different commit. Empty or
    unknown evidence SHAs are also rejected.
    """
    evidence_sha = str((bundle.subject or {}).get("head_sha", "") or "").strip()
    target = (head_sha or "").strip()
    if not target:
        raise StaleCheckRunError("missing target head SHA for check-run emission")
    if not evidence_sha or evidence_sha == "unknown":
        raise StaleCheckRunError(
            f"evidence subject head_sha is missing/unknown; refusing check-run for {target}"
        )
    if evidence_sha != target:
        raise StaleCheckRunError(
            f"stale check-run SHA mismatch: evidence={evidence_sha} target={target}"
        )


def build_check_output(bundle: EvidenceBundle, *, markdown_summary: str | None = None) -> dict[str, Any]:
    """Build GitHub check-run output payload from an evidence bundle."""
    decision_state = _decision_state_from_bundle(bundle)
    recommendation = str(
        bundle.decision.get("merge_recommendation")
        or bundle.decision.get("decision_state")
        or "needs_review"
    )
    summary = markdown_summary or f"OVK decision: {decision_state} (alias: {recommendation})"
    return {
        "title": f"OVK verification: {decision_state}",
        "summary": summary[:65535],
    }


def build_check_run_payload(
    bundle: EvidenceBundle,
    *,
    head_sha: str,
    markdown_summary: str | None = None,
    validate_sha: bool = True,
) -> dict[str, Any]:
    """Build a completed GitHub check-run request body.

    Includes a stable ``external_id`` so reruns and concurrent emitters update
    the same check run for a given repository head SHA.
    """
    if validate_sha:
        validate_check_run_head_sha(bundle, head_sha)
    decision_state = _decision_state_from_bundle(bundle)
    repo = str((bundle.subject or {}).get("repo", "unknown/repo") or "unknown/repo")
    return {
        "name": CHECK_NAME,
        "head_sha": head_sha,
        "external_id": check_run_external_id(repo=repo, head_sha=head_sha),
        "status": "completed",
        "conclusion": check_conclusion_for_recommendation(decision_state),
        "output": build_check_output(bundle, markdown_summary=markdown_summary),
    }
