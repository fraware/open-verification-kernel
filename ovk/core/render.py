"""Render OVK evidence for humans."""

from __future__ import annotations

from ovk.core.counterexample_translator import repair_hint_for_counterexample
from ovk.core.models import EvidenceBundle, VerificationEvidence


def _section_kind(evidence: VerificationEvidence) -> str:
    """Classify the primary failure/outcome section for enforced evidence."""
    recommendation = str(evidence.decision.get("merge_recommendation", "require_human_review"))
    artifacts = evidence.generated_artifacts or []
    kinds = {str(item.get("kind")) for item in artifacts if isinstance(item, dict)}
    if "incomplete_abstraction" in kinds or (
        isinstance(evidence.coverage, dict)
        and evidence.coverage.get("status") in {"partial", "unknown"}
        and recommendation == "require_human_review"
        and "incomplete" in str(evidence.decision.get("aggregation_reason", ""))
    ):
        return "incomplete_abstraction"
    if "backend_disagreement" in kinds:
        return "disagreement"
    if "quality_error" in kinds:
        return "evidence_quality_failure"
    statuses = {claim.status.value for claim in evidence.backend_claims}
    if "fail" in statuses:
        return "property_failure"
    if statuses & {"unknown", "error", "timeout"} or recommendation == "require_human_review":
        if any(claim.status.value in {"unknown", "error"} for claim in evidence.backend_claims):
            return "unavailability"
    if recommendation == "block":
        return "property_failure"
    return "outcome"


def render_evidence_markdown(evidence: VerificationEvidence) -> str:
    """Render one evidence object as a concise PR-ready Markdown section."""
    intent_title = evidence.intent.get("title", evidence.intent.get("intent_id", "unknown intent"))
    lines = [f"### {intent_title}", ""]

    section = _section_kind(evidence)
    lines.append(f"Outcome class: `{section}`")
    lines.append("")

    severity = None
    if isinstance(evidence.intent.get("risk"), dict):
        severity = evidence.intent["risk"].get("severity")
    if severity:
        lines.append(f"Severity: `{severity}`")
        lines.append("")

    if evidence.obligation_id or evidence.routing_id or evidence.compiler:
        lines.append("Control plane:")
        if evidence.obligation_id:
            lines.append(f"- Obligation: `{evidence.obligation_id}`")
        if evidence.routing_id:
            lines.append(f"- Routing: `{evidence.routing_id}`")
        if evidence.compiler:
            compiler_id = evidence.compiler.get("compiler_id")
            compiler_version = evidence.compiler.get("compiler_version")
            lines.append(f"- Compiler: `{compiler_id}` @ `{compiler_version}`")
        if evidence.coverage:
            cov = evidence.coverage
            lines.append(
                f"- Coverage: `{cov.get('status')}` (confidence={cov.get('confidence')}, "
                f"extracted={cov.get('extracted_elements')})"
            )
        if evidence.materials:
            lines.append(f"- Materials: {len(evidence.materials)} referenced")
            for material in evidence.materials[:5]:
                if isinstance(material, dict):
                    lines.append(
                        f"  - `{material.get('kind')}` `{material.get('uri')}` "
                        f"sha256=`{(material.get('sha256') or '')[:12]}`"
                    )
        if evidence.selected_backends is not None:
            lines.append(f"- Selected: {', '.join(f'`{item}`' for item in evidence.selected_backends) or 'none'}")
        if evidence.executed_backends is not None:
            lines.append(f"- Executed: {', '.join(f'`{item}`' for item in evidence.executed_backends) or 'none'}")
        if evidence.requested_backends is not None:
            lines.append(
                f"- Primary/optional requested: "
                f"{', '.join(f'`{item}`' for item in evidence.requested_backends) or 'none'}"
            )
        if evidence.aggregation_policy:
            lines.append(f"- Aggregation: `{evidence.aggregation_policy}`")
        lines.append(f"- Routing enforced: `{evidence.routing_enforced}`")
        lines.append("")

    for claim in evidence.backend_claims:
        native = None
        for artifact in evidence.generated_artifacts or []:
            if (
                isinstance(artifact, dict)
                and artifact.get("kind") == "backend_provenance"
                and artifact.get("backend") == claim.backend
            ):
                native = artifact.get("native_execution")
        lines.extend(
            [
                f"- Backend: `{claim.backend}`",
                f"- Guarantee: `{claim.guarantee_type}`",
                f"- Status: `{claim.status.value}`",
            ]
        )
        if native is not None:
            lines.append(f"- Native execution: `{native}`")
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
            lines.append(f"- `{hint['fix_class']}`: {hint['suggested_action']}{location}")

    open_items = [
        item
        for item in (evidence.generated_artifacts or [])
        if isinstance(item, dict)
        and item.get("kind")
        in {"backend_disagreement", "quality_error", "incomplete_abstraction", "aggregation_warning"}
    ]
    if open_items:
        lines.extend(["", "Open obligations:"])
        for item in open_items:
            lines.append(f"- `{item.get('kind')}`: {item.get('reason') or item.get('resolution') or item}")

    recommendation = evidence.decision.get("merge_recommendation", "require_human_review")
    lines.extend(["", f"Recommendation: `{recommendation}`"])
    if evidence.decision.get("aggregation_reason"):
        lines.append(f"Reason: {evidence.decision['aggregation_reason']}")
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
