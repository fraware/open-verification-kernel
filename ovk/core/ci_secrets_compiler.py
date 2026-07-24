"""Backend-neutral CI secrets obligation compiler."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ovk.core.bundle import content_digest
from ovk.core.compiler_bridge import (
    compile_github_actions_irs,
    github_actions_coverage,
    github_actions_to_lane_input,
    material_refs_from_digest,
)
from ovk.core.execution_models import (
    AbstractionCoverage,
    VerificationObligation,
    compute_abstraction_digest,
    compute_obligation_id,
)
from ovk.core.materials import material_reference_from_payload
from ovk.core.models import RiskSeverity, VerificationSubject

COMPILER_ID = "ovk.ci_secrets.neutral.v1"
COMPILER_VERSION = "0.2.0"
GITHUB_ACTIONS_COMPILER_ID = "ovk.github_actions.trust_flow.v1"


def compile_ci_secrets_obligation(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
    policy_digest: str | None = None,
    policy: dict[str, Any] | None = None,
) -> VerificationObligation:
    """Compile a backend-neutral CI secrets boundary obligation.

    When workflow YAML documents (``yaml`` / ``document`` / Actions shape) are
    present, the GitHub Actions trust-flow compiler participates. Legacy
    normalized workflow abstractions remain supported.
    """
    repo_root = Path(str(data["repo_root"])) if data.get("repo_root") else None
    irs = compile_github_actions_irs(data, repo_root=repo_root)
    trust_context = str(data.get("trust_context") or "untrusted_fork_pr")
    legacy_workflows = data.get("workflows") if isinstance(data.get("workflows"), list) else []

    if irs:
        lane_input = github_actions_to_lane_input(
            irs,
            trust_context=trust_context,
            legacy_workflows=[item for item in legacy_workflows if isinstance(item, dict)],
        )
        for key in ("author_type", "agent", "task"):
            if key in data:
                lane_input[key] = data[key]
        coverage = github_actions_coverage(irs, workflow_count=len(lane_input["workflows"]))
        materials = [
            material_refs_from_digest(
                material_id=content_digest({"wf": index})[:32],
                kind="workflow",
                uri=f"ovk-material:ci_secrets/workflow/{index}",
                payload=ir.model_dump(mode="json"),
                source_revision=head_sha,
            )
            for index, ir in enumerate(irs)
        ]
        abstraction = {
            "kind": "ci_secrets_workflow_boundary",
            "input": lane_input,
            "github_actions_irs": [ir.model_dump(mode="json") for ir in irs],
            "source_compiler": GITHUB_ACTIONS_COMPILER_ID,
        }
        compiler_id = GITHUB_ACTIONS_COMPILER_ID
    else:
        warnings: list[str] = []
        if not legacy_workflows:
            coverage = AbstractionCoverage(
                status="unknown",
                confidence=0.0,
                extracted_elements=0,
                expected_elements=None,
                warnings=["workflow abstraction missing or empty"],
            )
            extracted = 0
        else:
            extracted = len(legacy_workflows)
            if not isinstance(data.get("trust_context"), str) or not data.get("trust_context"):
                warnings.append("trust_context missing; checker may treat context as unknown")
            coverage = AbstractionCoverage(
                status="complete" if not warnings else "partial",
                confidence=1.0 if not warnings else 0.7,
                extracted_elements=extracted,
                expected_elements=extracted,
                warnings=warnings,
            )
        lane_input = data
        materials = [
            material_reference_from_payload(
                material_id="ci-secrets-input",
                kind="diff",
                uri="ovk-material:ci_secrets/input",
                payload=data,
                source_revision=head_sha,
                trusted=False,
            )
        ]
        abstraction = {
            "kind": "ci_secrets_workflow_boundary",
            "input": lane_input,
            "source_compiler": None,
        }
        compiler_id = COMPILER_ID

    provisional = VerificationObligation(
        obligation_id="pending",
        subject=VerificationSubject(repo=repo, head_sha=head_sha, base_sha=base_sha),
        intent_id="no-secrets-in-untrusted-context",
        intent_version="0.1.0",
        lane="ci_secrets",
        property_kind="safety",
        severity=RiskSeverity.CRITICAL,
        compiler_id=compiler_id,
        compiler_version=COMPILER_VERSION,
        materials=materials,
        abstraction=abstraction,
        abstraction_digest=compute_abstraction_digest(abstraction),
        coverage=coverage,
        acceptable_guarantees=["workflow_secrets_boundary_check"],
        required_capabilities=["ci_secrets"],
        policy_digest=policy_digest or content_digest({"lane": "ci_secrets", "policy": policy or {}}),
    )
    return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})
