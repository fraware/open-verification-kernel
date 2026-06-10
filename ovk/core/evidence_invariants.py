"""Evidence bundle invariant checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ovk.core.bundle import content_digest
from ovk.core.models import EvidenceBundle, VerificationStatus


@dataclass(frozen=True)
class EvidenceInvariantIssue:
    """One evidence invariant issue."""

    path: str
    message: str
    severity: str = "error"

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "message": self.message, "severity": self.severity}


def _decision_value(data: dict[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    return str(value)


def _assumption_texts(claim: Any) -> str:
    return " ".join(str(item) for item in claim.assumptions).lower()


def _backend_provenance_names(evidence: Any) -> set[str]:
    names: set[str] = set()
    for artifact in evidence.generated_artifacts:
        if artifact.get("kind") == "backend_provenance":
            backend = artifact.get("backend")
            if backend is not None:
                names.add(str(backend).lower())
    return names


def check_evidence_bundle_invariants(bundle: EvidenceBundle) -> list[EvidenceInvariantIssue]:
    """Check conservative invariants over an evidence bundle."""
    issues: list[EvidenceInvariantIssue] = []
    if not bundle.evidence:
        issues.append(EvidenceInvariantIssue(path="evidence", message="bundle must contain at least one evidence item"))
        return issues

    seen_ids: set[str] = set()
    for index, evidence in enumerate(bundle.evidence):
        evidence_path = f"evidence[{index}]"
        if evidence.evidence_id in seen_ids:
            issues.append(
                EvidenceInvariantIssue(
                    path=f"{evidence_path}.evidence_id",
                    message=f"duplicate evidence_id: {evidence.evidence_id}",
                )
            )
        seen_ids.add(evidence.evidence_id)

        if not evidence.backend_claims:
            issues.append(
                EvidenceInvariantIssue(
                    path=f"{evidence_path}.backend_claims",
                    message="evidence item must include at least one backend claim",
                )
            )

        intent_risk = str(evidence.intent.get("risk", {}).get("severity", "medium")).lower()
        provenance = evidence.intent.get("provenance", {}) or {}
        inferred_intent = provenance.get("inferred") is True
        evidence_recommendation = _decision_value(evidence.decision, "merge_recommendation")
        if intent_risk in {"high", "critical"} and inferred_intent:
            for claim_index, claim in enumerate(evidence.backend_claims):
                if claim.status == VerificationStatus.PASS and evidence_recommendation == "allow":
                    if evidence.decision.get("human_review_required") is not True:
                        issues.append(
                            EvidenceInvariantIssue(
                                path=f"{evidence_path}.backend_claims[{claim_index}].status",
                                message=(
                                    "inferred high-risk intent cannot produce allow without template "
                                    "provenance or human confirmation (OVK-INV-005)"
                                ),
                            )
                        )
        if evidence_recommendation is None:
            issues.append(
                EvidenceInvariantIssue(
                    path=f"{evidence_path}.decision.merge_recommendation",
                    message="evidence decision must include merge_recommendation",
                )
            )

        evidence_head = str(evidence.subject.get("head_sha", ""))
        bundle_head = str(bundle.subject.get("head_sha", ""))
        if evidence_head and bundle_head and evidence_head != bundle_head:
            issues.append(
                EvidenceInvariantIssue(
                    path=f"{evidence_path}.subject.head_sha",
                    message="evidence subject head_sha must match bundle subject (OVK-INV-008)",
                )
            )

        has_input_digest = any(artifact.get("kind") == "input_digest" for artifact in evidence.generated_artifacts)
        if not has_input_digest:
            issues.append(
                EvidenceInvariantIssue(
                    path=f"{evidence_path}.generated_artifacts",
                    message="evidence must include an input_digest artifact (OVK-INV-003)",
                    severity="warning",
                )
            )

        for claim_index, claim in enumerate(evidence.backend_claims):
            claim_path = f"{evidence_path}.backend_claims[{claim_index}]"
            if not claim.assumptions:
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{claim_path}.assumptions",
                        message="backend claim must declare assumptions (OVK-INV-003)",
                    )
                )
            if not claim.limits:
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{claim_path}.limits",
                        message="backend claim must declare limits (OVK-INV-003)",
                    )
                )
            if not claim.adapter_version and not claim.tool_version:
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{claim_path}.adapter_version",
                        message="backend claim must include adapter_version or tool_version (OVK-INV-003)",
                    )
                )
            if claim.status in {VerificationStatus.UNKNOWN, VerificationStatus.ERROR}:
                if evidence_recommendation == "allow":
                    issues.append(
                        EvidenceInvariantIssue(
                            path=f"{claim_path}.status",
                            message="unknown or error backend claim must not produce allow recommendation",
                        )
                    )
                if evidence.decision.get("human_review_required") is not True:
                    issues.append(
                        EvidenceInvariantIssue(
                            path=f"{evidence_path}.decision.human_review_required",
                            message="unknown or error backend claim must require human review",
                        )
                    )
            if claim.status == VerificationStatus.FAIL and evidence_recommendation == "allow":
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{claim_path}.status",
                        message="failing backend claim must not produce allow recommendation",
                    )
                )
            assumptions_text = " ".join(claim.assumptions).lower()
            if claim.guarantee_type == "native_tool" and (
                "deterministic oracle" in assumptions_text
                or "deterministic fallback" in assumptions_text
                or "binary unavailable" in assumptions_text
            ):
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{claim_path}.guarantee_type",
                        message=(
                            "backend claim must not advertise native_tool when deterministic "
                            "oracle or fallback assumptions are present (OVK-INV-NATIVE-HONESTY)"
                        ),
                    )
                )
            for artifact in evidence.generated_artifacts:
                if artifact.get("kind") != "backend_provenance":
                    continue
                if artifact.get("backend") and str(artifact.get("backend")).lower() != claim.backend.lower():
                    continue
                if artifact.get("used_native_binary") is True and "deterministic oracle" in assumptions_text:
                    issues.append(
                        EvidenceInvariantIssue(
                            path=f"{evidence_path}.generated_artifacts",
                            message=(
                                "backend provenance must not claim native execution when "
                                "deterministic oracle assumptions are present (OVK-INV-NATIVE-HONESTY)"
                            ),
                        )
                    )

    bundle_recommendation = _decision_value(bundle.decision, "merge_recommendation")
    if bundle_recommendation is None:
        issues.append(
            EvidenceInvariantIssue(
                path="decision.merge_recommendation",
                message="bundle decision must include merge_recommendation",
            )
        )
    if any(issue.severity == "error" for issue in issues) and bundle_recommendation == "allow":
        issues.append(
            EvidenceInvariantIssue(
                path="decision.merge_recommendation",
                message="bundle with invariant errors must not recommend allow",
            )
        )

    if bundle.evidence:
        subject = bundle.evidence[0].subject
        fingerprint = content_digest(
            {"subject": subject, "evidence": [item.model_dump(mode="json") for item in bundle.evidence]}
        )[:16]
        expected_bundle_id = f"bundle-{fingerprint}"
        if bundle.bundle_id != expected_bundle_id:
            issues.append(
                EvidenceInvariantIssue(
                    path="bundle_id",
                    message="bundle_id must be content-addressed from subject and evidence (OVK-INV-008)",
                )
            )
    return issues
