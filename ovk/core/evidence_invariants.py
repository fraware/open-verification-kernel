"""Evidence bundle invariant checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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

        evidence_recommendation = _decision_value(evidence.decision, "merge_recommendation")
        if evidence_recommendation is None:
            issues.append(
                EvidenceInvariantIssue(
                    path=f"{evidence_path}.decision.merge_recommendation",
                    message="evidence decision must include merge_recommendation",
                )
            )

        for claim_index, claim in enumerate(evidence.backend_claims):
            claim_path = f"{evidence_path}.backend_claims[{claim_index}]"
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
    return issues
