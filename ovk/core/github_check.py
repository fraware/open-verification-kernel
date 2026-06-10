"""GitHub check-run helpers for OVK merge recommendations."""

from __future__ import annotations

from typing import Any

from ovk.core.models import EvidenceBundle


CHECK_NAME = "Open Verification Kernel"

CONCLUSION_BY_RECOMMENDATION = {
    "allow": "success",
    "block": "failure",
    "require_human_review": "neutral",
    "allow_with_warning": "success",
    "require_stronger_check": "neutral",
}


def check_conclusion_for_recommendation(recommendation: str) -> str:
    """Map an OVK merge recommendation to a GitHub check conclusion."""
    return CONCLUSION_BY_RECOMMENDATION.get(recommendation, "neutral")


def build_check_output(bundle: EvidenceBundle, *, markdown_summary: str | None = None) -> dict[str, Any]:
    """Build GitHub check-run output payload from an evidence bundle."""
    recommendation = str(bundle.decision.get("merge_recommendation", "require_human_review"))
    summary = markdown_summary or f"OVK merge recommendation: {recommendation}"
    return {
        "title": f"OVK verification: {recommendation}",
        "summary": summary[:65535],
    }


def build_check_run_payload(
    bundle: EvidenceBundle,
    *,
    head_sha: str,
    markdown_summary: str | None = None,
) -> dict[str, Any]:
    """Build a completed GitHub check-run request body."""
    recommendation = str(bundle.decision.get("merge_recommendation", "require_human_review"))
    return {
        "name": CHECK_NAME,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": check_conclusion_for_recommendation(recommendation),
        "output": build_check_output(bundle, markdown_summary=markdown_summary),
    }
