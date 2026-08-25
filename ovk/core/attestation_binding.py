"""Attestation and evidence binding checks (OVK-INV-008)."""

from __future__ import annotations

from typing import Any

from ovk.core.bundle import content_digest
from ovk.core.evidence_invariants import EvidenceInvariantIssue
from ovk.core.models import EvidenceBundle


def _issue(path: str, message: str) -> EvidenceInvariantIssue:
    return EvidenceInvariantIssue(path=path, message=message)


def _expected_attestation_evidence_item(evidence: Any) -> dict[str, Any]:
    return {
        "intent_id": evidence.intent.get("intent_id"),
        "title": evidence.intent.get("title"),
        "severity": (evidence.intent.get("risk") or {}).get("severity")
        if isinstance(evidence.intent.get("risk"), dict)
        else None,
        "claims": [claim.model_dump(mode="json") for claim in evidence.backend_claims],
        "counterexamples": evidence.counterexamples,
        "decision": evidence.decision,
        "obligation_id": evidence.obligation_id,
        "routing_id": evidence.routing_id,
        "material_set_digest": evidence.material_set_digest,
        "compiler": evidence.compiler,
        "coverage": evidence.coverage,
        "materials": evidence.materials,
        "requested_backends": evidence.requested_backends,
        "eligible_backends": evidence.eligible_backends,
        "selected_backends": evidence.selected_backends,
        "executed_backends": evidence.executed_backends,
        "aggregation_policy": evidence.aggregation_policy,
        "routing_enforced": evidence.routing_enforced,
        "open_artifacts": [
            item
            for item in (evidence.generated_artifacts or [])
            if isinstance(item, dict)
            and item.get("kind")
            in {
                "backend_disagreement",
                "quality_error",
                "incomplete_abstraction",
                "backend_provenance",
            }
        ],
    }


def _evidence_mismatch_message(key: str) -> str:
    if key == "routing_id":
        return "evidence and attestation routing IDs disagree (OVK-INV-020)"
    if key == "material_set_digest":
        return "evidence and attestation material_set_digest disagree (OVK-INV-021)"
    return f"attestation evidence field {key!r} does not match bundle evidence"


def verify_bundle_statement_binding(bundle: EvidenceBundle, statement: dict[str, Any]) -> list[EvidenceInvariantIssue]:
    """Verify an attestation statement is exactly derived from the evidence bundle."""
    issues: list[EvidenceInvariantIssue] = []
    bundle_payload = bundle.model_dump(mode="json")
    expected_digest = content_digest(bundle_payload)

    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        issues.append(_issue("_type", "attestation statement type is not in-toto Statement/v1"))
    if statement.get("predicateType") != "https://openverification.dev/predicate/verification/v1":
        issues.append(_issue("predicateType", "attestation predicateType is not the OVK verification predicate"))

    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return issues + [_issue("predicate", "attestation predicate is missing")]
    verification = predicate.get("verification")
    if not isinstance(verification, dict):
        return issues + [_issue("predicate.verification", "attestation verification predicate is missing")]

    stated_digest = verification.get("bundle_digest")
    if stated_digest != expected_digest:
        issues.append(
            _issue(
                "predicate.verification.bundle_digest",
                "attestation bundle_digest does not match evidence bundle content",
            )
        )

    bundle_head = str(bundle.subject.get("head_sha", ""))
    bundle_repo = str(bundle.subject.get("repo", ""))
    subjects = statement.get("subject", [])
    if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], dict):
        issues.append(_issue("subject", "attestation must contain exactly one repository subject"))
    else:
        stated_name = subjects[0].get("name")
        expected_name = f"git+https://github.com/{bundle_repo}"
        if stated_name != expected_name:
            issues.append(_issue("subject[0].name", "attestation repository subject does not match bundle repo"))
        commit_digest = subjects[0].get("digest")
        stated_sha = commit_digest.get("gitCommit") if isinstance(commit_digest, dict) else None
        if stated_sha != bundle_head:
            issues.append(
                _issue(
                    "subject[0].digest.gitCommit",
                    "attestation commit SHA does not match bundle subject head_sha",
                )
            )

    if verification.get("bundle_id") != bundle.bundle_id:
        issues.append(
            _issue(
                "predicate.verification.bundle_id",
                "attestation bundle_id does not match evidence bundle",
            )
        )
    if verification.get("schema_version") != bundle.schema_version:
        issues.append(_issue("predicate.verification.schema_version", "attestation bundle schema_version mismatch"))
    if verification.get("decision") != bundle.decision:
        issues.append(_issue("predicate.verification.decision", "attestation decision does not match bundle decision"))
    if verification.get("open_obligations") != bundle.open_obligations:
        issues.append(
            _issue(
                "predicate.verification.open_obligations",
                "attestation open_obligations do not match bundle",
            )
        )

    evidence_items = verification.get("evidence")
    if not isinstance(evidence_items, list):
        issues.append(_issue("predicate.verification.evidence", "attestation evidence list is missing"))
        return issues
    if len(evidence_items) != len(bundle.evidence):
        issues.append(
            _issue(
                "predicate.verification.evidence",
                "attestation evidence count does not match bundle evidence count",
            )
        )

    for index, evidence in enumerate(bundle.evidence):
        if index >= len(evidence_items) or not isinstance(evidence_items[index], dict):
            issues.append(
                _issue(
                    f"predicate.verification.evidence[{index}]",
                    "attestation evidence entry is missing",
                )
            )
            continue
        observed = evidence_items[index]
        expected = _expected_attestation_evidence_item(evidence)
        for key, expected_value in expected.items():
            if observed.get(key) != expected_value:
                issues.append(
                    _issue(
                        f"predicate.verification.evidence[{index}].{key}",
                        _evidence_mismatch_message(key),
                    )
                )
        extra = sorted(set(observed) - set(expected))
        if extra:
            issues.append(
                _issue(
                    f"predicate.verification.evidence[{index}]",
                    f"attestation evidence contains non-derived fields: {extra}",
                )
            )
    return issues


def verify_envelope_manifest_binding(envelope: dict[str, Any], *, manifest_sha256: str) -> list[EvidenceInvariantIssue]:
    """Verify an attestation envelope references the correct artifact manifest hash."""
    issues: list[EvidenceInvariantIssue] = []
    manifest = envelope.get("artifact_manifest", {})
    stated_sha = str(manifest.get("sha256", ""))
    if not stated_sha:
        issues.append(
            _issue(
                "artifact_manifest.sha256",
                "attestation envelope must bind an artifact manifest digest",
            )
        )
    elif manifest_sha256 and stated_sha != manifest_sha256:
        issues.append(
            _issue(
                "artifact_manifest.sha256",
                "envelope manifest digest does not match artifact manifest file",
            )
        )
    return issues
