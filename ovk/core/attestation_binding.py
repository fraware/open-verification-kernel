"""Attestation and evidence binding checks (OVK-INV-008)."""

from __future__ import annotations

from typing import Any

from ovk.core.bundle import content_digest
from ovk.core.evidence_invariants import EvidenceInvariantIssue
from ovk.core.models import EvidenceBundle


def verify_bundle_statement_binding(bundle: EvidenceBundle, statement: dict[str, Any]) -> list[EvidenceInvariantIssue]:
    """Verify an attestation statement is bound to the evidence bundle and commit SHA."""
    issues: list[EvidenceInvariantIssue] = []
    bundle_payload = bundle.model_dump(mode="json")
    expected_digest = content_digest(bundle_payload)
    verification = statement.get("predicate", {}).get("verification", {})
    stated_digest = str(verification.get("bundle_digest", ""))
    if stated_digest and stated_digest != expected_digest:
        issues.append(
            EvidenceInvariantIssue(
                path="predicate.verification.bundle_digest",
                message="attestation bundle_digest does not match evidence bundle content",
            )
        )

    bundle_head = str(bundle.subject.get("head_sha", ""))
    subjects = statement.get("subject", [])
    if isinstance(subjects, list) and subjects:
        commit_digest = subjects[0].get("digest", {}) if isinstance(subjects[0], dict) else {}
        stated_sha = str(commit_digest.get("gitCommit", ""))
        if bundle_head and stated_sha and bundle_head != stated_sha:
            issues.append(
                EvidenceInvariantIssue(
                    path="subject[0].digest.gitCommit",
                    message="attestation commit SHA does not match bundle subject head_sha",
                )
            )

    stated_bundle_id = str(verification.get("bundle_id", ""))
    if stated_bundle_id and stated_bundle_id != bundle.bundle_id:
        issues.append(
            EvidenceInvariantIssue(
                path="predicate.verification.bundle_id",
                message="attestation bundle_id does not match evidence bundle",
            )
        )

    # OVK-INV-020: evidence and attestation routing IDs agree.
    evidence_items = verification.get("evidence", [])
    if isinstance(evidence_items, list):
        for index, evidence in enumerate(bundle.evidence):
            if not evidence.routing_id:
                continue
            if index >= len(evidence_items) or not isinstance(evidence_items[index], dict):
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"predicate.verification.evidence[{index}].routing_id",
                        message="attestation evidence entry missing for routing ID binding (OVK-INV-020)",
                    )
                )
                continue
            stated_routing = evidence_items[index].get("routing_id")
            if stated_routing != evidence.routing_id:
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"predicate.verification.evidence[{index}].routing_id",
                        message="evidence and attestation routing IDs disagree (OVK-INV-020)",
                    )
                )
            stated_material_set = evidence_items[index].get("material_set_digest")
            if evidence.material_set_digest and stated_material_set != evidence.material_set_digest:
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"predicate.verification.evidence[{index}].material_set_digest",
                        message="evidence and attestation material_set_digest disagree (OVK-INV-021)",
                    )
                )
    return issues


def verify_envelope_manifest_binding(envelope: dict[str, Any], *, manifest_sha256: str) -> list[EvidenceInvariantIssue]:
    """Verify an attestation envelope references the correct artifact manifest hash."""
    issues: list[EvidenceInvariantIssue] = []
    manifest = envelope.get("artifact_manifest", {})
    stated_sha = str(manifest.get("sha256", ""))
    if stated_sha and manifest_sha256 and stated_sha != manifest_sha256:
        issues.append(
            EvidenceInvariantIssue(
                path="artifact_manifest.sha256",
                message="envelope manifest digest does not match artifact manifest file",
            )
        )
    return issues
