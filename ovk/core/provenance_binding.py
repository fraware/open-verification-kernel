"""Semantic binding checks between OVK provenance and evidence bundles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ovk.core.bundle import content_digest
from ovk.core.models import EvidenceBundle


@dataclass(frozen=True)
class ProvenanceBindingIssue:
    path: str
    message: str


def _expected_control_plane(bundle: EvidenceBundle) -> dict[str, Any]:
    return {
        "obligation_ids": [item.obligation_id for item in bundle.evidence if item.obligation_id],
        "routing_ids": [item.routing_id for item in bundle.evidence if item.routing_id],
        "material_set_digests": [item.material_set_digest for item in bundle.evidence if item.material_set_digest],
        "routing_enforced": [bool(item.routing_enforced) for item in bundle.evidence],
        "compilers": [item.compiler for item in bundle.evidence if item.compiler],
        "coverage": [item.coverage for item in bundle.evidence if item.coverage],
        "selected_backends": [item.selected_backends for item in bundle.evidence],
        "executed_backends": [item.executed_backends for item in bundle.evidence],
        "guarantees": [[claim.guarantee_type for claim in item.backend_claims] for item in bundle.evidence],
    }


def verify_provenance_binding(
    bundle: EvidenceBundle,
    provenance: dict[str, Any],
) -> list[ProvenanceBindingIssue]:
    """Verify provenance summary fields are exactly derived from *bundle*."""
    issues: list[ProvenanceBindingIssue] = []
    bundle_section = provenance.get("bundle")
    if not isinstance(bundle_section, dict):
        return [ProvenanceBindingIssue("bundle", "provenance bundle section is missing")]

    expected_digest = content_digest(bundle.model_dump(mode="json"))
    observed_digest = (bundle_section.get("digest") or {}).get("sha256") if isinstance(bundle_section.get("digest"), dict) else None
    if observed_digest != expected_digest:
        issues.append(ProvenanceBindingIssue("bundle.digest.sha256", "provenance bundle digest does not match evidence bundle"))
    if bundle_section.get("bundle_id") != bundle.bundle_id:
        issues.append(ProvenanceBindingIssue("bundle.bundle_id", "provenance bundle_id does not match evidence bundle"))
    if bundle_section.get("schema_version") != bundle.schema_version:
        issues.append(ProvenanceBindingIssue("bundle.schema_version", "provenance bundle schema_version does not match"))
    if bundle_section.get("decision") != bundle.decision:
        issues.append(ProvenanceBindingIssue("bundle.decision", "provenance decision does not exactly match bundle decision"))

    observed_control_plane = provenance.get("control_plane")
    expected_control_plane = _expected_control_plane(bundle)
    if observed_control_plane != expected_control_plane:
        if not isinstance(observed_control_plane, dict):
            issues.append(ProvenanceBindingIssue("control_plane", "provenance control_plane section is missing"))
        else:
            for key, expected in expected_control_plane.items():
                if observed_control_plane.get(key) != expected:
                    issues.append(
                        ProvenanceBindingIssue(
                            f"control_plane.{key}",
                            f"provenance {key} does not match evidence-derived value",
                        )
                    )
            extra = sorted(set(observed_control_plane) - set(expected_control_plane))
            if extra:
                issues.append(
                    ProvenanceBindingIssue(
                        "control_plane",
                        f"provenance control_plane contains non-derived fields: {extra}",
                    )
                )
    return issues
