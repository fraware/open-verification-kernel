"""Render OVK evidence for humans."""

from __future__ import annotations

from ovk.core.counterexample_translator import repair_hint_for_counterexample
from ovk.core.models import EvidenceBundle, VerificationEvidence


def render_evidence_markdown(evidence: VerificationEvidence) -> str:
    """Render one evidence object as a concise PR-ready Markdown section."""
    intent_title = evidence.intent.get("title", evidence.intent.get("intent_id", "unknown intent"))
    lines = [f"### {intent_title}", ""]

    for claim in evidence.backend_claims:
        lines.extend(
            [
                f"- Backend: `{claim.backend}`",
                f"- Guarantee: `{claim.guarantee_type}`",
                f"- Status: `{claim.status.value}`",
            ]
        )
        if claim.assumptions:
            lines.append("- Assumptions:")
            lines.extend(f"  - {item}" for item in claim.assumptions)
        if claim.limits:
            lines.append("- Limits:")
            lines.extend(f"  - {item}" for item in claim.limits)

    if evidence.counterexamples:
        lines.extend(["", "Counterexamples:"])
        for counterexample in evidence.counterexamples:
            summary = counterexample.get("summary", "counterexample available")
            failure_mode = counterexample.get("failure_mode", "unknown_failure_mode")
            affected_file = counterexample.get("affected_file")
            suffix = f" in `{affected_file}`" if affected_file else ""
            lines.append(f"- `{failure_mode}`: {summary}{suffix}")
        lines.extend(["", "Suggested repairs:"])
        for hint in (repair_hint_for_counterexample(item) for item in evidence.counterexamples):
            location = ""
            if hint.get("affected_file"):
                location = f" (`{hint['affected_file']}`"
                if hint.get("line_hunk") is not None:
                    location += f", line {hint['line_hunk']}"
                location += ")"
            lines.append(
                f"- `{hint['fix_class']}`: {hint['suggested_action']}{location}"
            )

    recommendation = evidence.decision.get("merge_recommendation", "require_human_review")
    lines.extend(["", f"Recommendation: `{recommendation}`"])
    return "\n".join(lines)


def render_bundle_markdown(bundle: EvidenceBundle) -> str:
    """Render an evidence bundle as a PR-ready Markdown comment."""
    recommendation = bundle.decision.get("merge_recommendation", "require_human_review")
    subject = bundle.subject
    lines = [
        "## Open Verification Kernel",
        "",
        f"Repository: `{subject.get('repo', 'unknown')}`",
        f"Head SHA: `{subject.get('head_sha', 'unknown')}`",
        f"Merge recommendation: `{recommendation}`",
        "",
    ]
    for evidence in bundle.evidence:
        lines.append(render_evidence_markdown(evidence))
        lines.append("")
    if bundle.open_obligations:
        lines.append("Open obligations:")
        for obligation in bundle.open_obligations:
            lines.append(f"- {obligation}")
    return "\n".join(lines).strip() + "\n"
