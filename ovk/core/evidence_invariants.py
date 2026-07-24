"""Evidence bundle invariant checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ovk.core.bundle import content_digest
from ovk.core.materials import compute_material_set_digest
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

    issues.extend(_check_control_plane_invariants(bundle))
    return issues


def _check_control_plane_invariants(bundle: EvidenceBundle) -> list[EvidenceInvariantIssue]:
    """Evaluate OVK-INV-009 through OVK-INV-020 for evidence v2 / enforced records."""
    issues: list[EvidenceInvariantIssue] = []
    for index, evidence in enumerate(bundle.evidence):
        path = f"evidence[{index}]"
        is_v2 = str(evidence.schema_version).endswith(".v2") or evidence.routing_enforced
        is_v3 = str(evidence.schema_version).endswith(".v3")
        if not is_v2 and not is_v3 and evidence.obligation_id is None and evidence.routing_id is None:
            continue

        selected = list(evidence.selected_backends or [])
        executed = list(evidence.executed_backends or [])
        attempted = list(evidence.attempted_backends or [])
        eligible = list(evidence.eligible_backends or [])
        attempts = list(evidence.execution_attempts or [])

        required_selected = selected  # v2 preview treats selected list as required execution set
        if sorted(required_selected) != sorted(executed) and evidence.routing_enforced:
            # Allow attempted-but-errored backends to appear in attempted without executed parity
            # only when attempts explicitly record them; otherwise flag INV-009.
            if sorted(required_selected) != sorted(attempted):
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{path}.selected_backends",
                        message="selected backends must equal required execution set (OVK-INV-009)",
                    )
                )

        for backend in executed:
            if eligible and backend not in eligible:
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{path}.executed_backends",
                        message=f"executed backend {backend!r} was not eligible (OVK-INV-010)",
                    )
                )
            if selected and backend not in selected:
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{path}.executed_backends",
                        message=f"executed backend {backend!r} was not selected (OVK-INV-010)",
                    )
                )

        if evidence.obligation_id:
            for attempt_index, attempt in enumerate(attempts):
                if not isinstance(attempt, dict):
                    continue
                # Attempts bind via backend_obligation_id / obligation linkage in control plane.
                if attempt.get("obligation_id") not in {None, evidence.obligation_id}:
                    issues.append(
                        EvidenceInvariantIssue(
                            path=f"{path}.execution_attempts[{attempt_index}]",
                            message="every attempt must refer to the evidence obligation (OVK-INV-011)",
                        )
                    )

        if evidence.routing_id is not None and not str(evidence.routing_id).strip():
            issues.append(
                EvidenceInvariantIssue(
                    path=f"{path}.routing_id",
                    message="routing ID must be present and non-empty (OVK-INV-012)",
                )
            )

        for claim_index, claim in enumerate(evidence.backend_claims):
            native_claimed = any(
                artifact.get("kind") == "backend_provenance"
                and str(artifact.get("backend", "")).lower() == claim.backend.lower()
                and artifact.get("native_execution") is True
                for artifact in evidence.generated_artifacts
            )
            if native_claimed:
                has_tool = bool(claim.tool_version) or any(
                    artifact.get("kind") == "backend_provenance"
                    and str(artifact.get("backend", "")).lower() == claim.backend.lower()
                    and (artifact.get("tool_digest") or artifact.get("termination"))
                    for artifact in evidence.generated_artifacts
                )
                if not has_tool:
                    issues.append(
                        EvidenceInvariantIssue(
                            path=f"{path}.backend_claims[{claim_index}]",
                            message="native claim requires native execution provenance (OVK-INV-013)",
                        )
                    )

        if evidence.aggregation_policy and evidence.decision.get("aggregation_reason") is None and evidence.routing_enforced:
            # aggregation_reason is optional on legacy decision dicts; required for enforced v2.
            if "aggregation_reason" not in evidence.decision:
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{path}.decision.aggregation_reason",
                        message="aggregate decision must record aggregation policy reason (OVK-INV-014)",
                    )
                )

        if evidence.materials:
            for material_index, material in enumerate(evidence.materials):
                if not isinstance(material, dict):
                    continue
                digest = material.get("sha256")
                if not digest:
                    issues.append(
                        EvidenceInvariantIssue(
                            path=f"{path}.materials[{material_index}].sha256",
                            message="material digests must be present (OVK-INV-015)",
                        )
                    )
            if is_v3 or evidence.routing_enforced:
                expected_material_set = compute_material_set_digest(evidence.materials)
                stated_material_set = evidence.material_set_digest
                if not stated_material_set:
                    issues.append(
                        EvidenceInvariantIssue(
                            path=f"{path}.material_set_digest",
                            message="evidence v3 must include material_set_digest (OVK-INV-021)",
                        )
                    )
                elif stated_material_set != expected_material_set:
                    issues.append(
                        EvidenceInvariantIssue(
                            path=f"{path}.material_set_digest",
                            message="material_set_digest must match recomputed canonical digest (OVK-INV-021)",
                        )
                    )

        coverage = evidence.coverage or {}
        recommendation = _decision_value(evidence.decision, "merge_recommendation")
        if recommendation == "allow" and isinstance(coverage, dict):
            status = str(coverage.get("status", ""))
            if status in {"unknown", "partial"} and evidence.routing_enforced:
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{path}.coverage",
                        message="coverage is insufficient for allow recommendation (OVK-INV-016)",
                        severity="error",
                    )
                )

        if evidence.decision.get("fallback_used") is True and evidence.decision.get("fallback_accepted") is not True:
            issues.append(
                EvidenceInvariantIssue(
                    path=f"{path}.decision",
                    message="fallback guarantee must be accepted by intent and policy (OVK-INV-017)",
                )
            )

        compiler = evidence.compiler or {}
        if evidence.routing_enforced:
            if not compiler.get("compiler_id") or not compiler.get("compiler_version"):
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{path}.compiler",
                        message="compiler identity must be present (OVK-INV-018)",
                    )
                )
            for claim_index, claim in enumerate(evidence.backend_claims):
                if not claim.adapter_version and not claim.tool_version:
                    issues.append(
                        EvidenceInvariantIssue(
                            path=f"{path}.backend_claims[{claim_index}]",
                            message="adapter or tool version must be present (OVK-INV-018)",
                        )
                    )

        # OVK-INV-019: cache identity participation is validated when cache metadata artifacts exist.
        cache_artifacts = [a for a in evidence.generated_artifacts if a.get("kind") == "cache_identity"]
        for artifact in cache_artifacts:
            if not artifact.get("environment_digest"):
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{path}.generated_artifacts",
                        message="execution environment fingerprint must participate in cache identity (OVK-INV-019)",
                    )
                )

        if is_v3 or evidence.routing_enforced:
            trace_artifacts = [a for a in evidence.generated_artifacts if a.get("kind") == "control_plane_trace"]
            if not trace_artifacts and is_v3:
                issues.append(
                    EvidenceInvariantIssue(
                        path=f"{path}.generated_artifacts",
                        message="evidence v3 must include control_plane_trace artifact (OVK-INV-022)",
                    )
                )
            elif trace_artifacts:
                trace = trace_artifacts[0]
                if trace.get("routing_id") not in {None, evidence.routing_id}:
                    issues.append(
                        EvidenceInvariantIssue(
                            path=f"{path}.generated_artifacts",
                            message="control_plane_trace routing_id must match evidence routing_id (OVK-INV-022)",
                        )
                    )
                trace_digest = trace.get("material_set_digest")
                if is_v3 and trace_digest and trace_digest != evidence.material_set_digest:
                    issues.append(
                        EvidenceInvariantIssue(
                            path=f"{path}.generated_artifacts",
                            message="control_plane_trace material_set_digest must match evidence (OVK-INV-021)",
                        )
                    )

        if evidence.routing_enforced and not evidence.routing_id:
            issues.append(
                EvidenceInvariantIssue(
                    path=f"{path}.routing_id",
                    message="enforced evidence must include routing_id for attestation binding (OVK-INV-020)",
                )
            )

    return issues
