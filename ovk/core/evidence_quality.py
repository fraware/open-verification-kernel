"""Evidence quality report helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ovk.core.evidence_invariants import EvidenceInvariantIssue, check_evidence_bundle_invariants
from ovk.core.models import EvidenceBundle


EVIDENCE_QUALITY_SCHEMA_VERSION = "ovk.evidence_quality.v1"


@dataclass(frozen=True)
class EvidenceQualityReport:
    """Structured evidence quality report."""

    bundle_id: str
    passed: bool
    issues: tuple[EvidenceInvariantIssue, ...]
    schema_version: str = EVIDENCE_QUALITY_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "bundle_id": self.bundle_id,
            "passed": self.passed,
            "issues": [issue.to_dict() for issue in self.issues],
        }


def build_evidence_quality_report(bundle: EvidenceBundle) -> EvidenceQualityReport:
    """Build a structured quality report for an evidence bundle."""
    issues = tuple(check_evidence_bundle_invariants(bundle))
    failed = any(issue.severity == "error" for issue in issues)
    return EvidenceQualityReport(
        bundle_id=bundle.bundle_id,
        passed=not failed,
        issues=issues,
    )
