"""Sprint 1 v0 self-protection runner."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ovk.adapters.opa import evaluate_self_protection
from ovk.core.attestation import bundle_to_statement
from ovk.core.bundle import make_bundle
from ovk.core.check_metadata import load_required_check_metadata
from ovk.core.changed_files import load_changed_files
from ovk.core.models import EvidenceBundle
from ovk.core.render import render_bundle_markdown
from ovk.core.self_protection_input import SelfProtectionMetadata, build_self_protection_input


@dataclass(frozen=True)
class Sprint1Result:
    """Outputs from the Sprint 1 runner."""

    bundle: EvidenceBundle
    markdown: str
    attestation: dict[str, Any]

    @property
    def recommendation(self) -> str:
        return str(self.bundle.decision.get("merge_recommendation", "require_human_review"))


def load_metadata(path: Path | None) -> dict[str, Any]:
    """Load optional base metadata for the self-protection runner."""
    if path is None:
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def build_metadata_from_inputs(
    *,
    metadata_path: Path | None = None,
    changed_files_path: Path | None = None,
    check_metadata_path: Path | None = None,
) -> dict[str, Any]:
    """Build a canonical metadata dictionary from separate runner inputs."""
    data = load_metadata(metadata_path)
    if changed_files_path is not None:
        data["changed_files"] = load_changed_files(changed_files_path)
    check_metadata = load_required_check_metadata(check_metadata_path)
    for key, value in check_metadata.items():
        if value is not None:
            data[key] = value
    return data


def run_sprint1_self_protection(
    *,
    metadata: dict[str, Any],
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> Sprint1Result:
    """Run the Sprint 1 self-protection path from normalized metadata."""
    structured = build_self_protection_input(
        SelfProtectionMetadata(
            actor_type=str(metadata.get("actor_type", metadata.get("author_type", "ai_agent"))),
            agent_id=str(metadata.get("agent_id", metadata.get("agent", "unknown"))),
            task=str(metadata.get("task", "unknown")),
            changed_files=[str(path) for path in metadata.get("changed_files", [])],
            before_required_checks=metadata.get("before_required_checks"),
            after_required_checks=metadata.get("after_required_checks"),
            before_workflow_permissions=metadata.get("before_workflow_permissions"),
            after_workflow_permissions=metadata.get("after_workflow_permissions"),
            ovk_gate_name=str(metadata.get("ovk_gate_name", "ovk-verify")),
        )
    )
    evidence = evaluate_self_protection(
        structured,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
    )
    bundle = make_bundle([evidence])
    return Sprint1Result(
        bundle=bundle,
        markdown=render_bundle_markdown(bundle),
        attestation=bundle_to_statement(bundle),
    )


def write_sprint1_outputs(
    result: Sprint1Result,
    *,
    evidence_output: Path,
    markdown_output: Path,
    attestation_output: Path,
) -> None:
    """Write Sprint 1 outputs to disk."""
    evidence_output.write_text(
        json.dumps(result.bundle.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_output.write_text(result.markdown, encoding="utf-8")
    attestation_output.write_text(json.dumps(result.attestation, indent=2) + "\n", encoding="utf-8")
