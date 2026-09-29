"""Governed repository manifest for durable assurance guarantees.

The canonical repository path is .verification/guarantees.json.

For pull-request evaluation, when a base SHA is available, the active assurance
target is always loaded from that trusted base revision. The workspace/head
manifest is loaded separately as a proposal and compared against the base.

This is intentionally stricter than relying only on a changed-files list:
base/head manifest content is compared directly whenever the base revision is
available. A PR can propose guarantee additions, removals, selector changes, or
other definition edits, but those proposals do not govern that PR's own
assurance run.

If the base revision itself is unavailable or its guarantee manifest is invalid,
OVK does not substitute an empty guarantee set. The assurance target is marked
unavailable and callers must fail closed.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from ovk.core.bundle import content_digest
from ovk.core.guarantee_graph import GuaranteeSpec
from ovk.core.schema_validation import load_json, require_schema_valid
from ovk.paths import schema_path


GUARANTEE_MANIFEST_REPOSITORY_PATH = ".verification/guarantees.json"
GUARANTEE_MANIFEST_SCHEMA_VERSION = "ovk.guarantee_manifest.v1"


class GuaranteeManifest(BaseModel):
    """Typed repository representation of durable guarantees."""

    schema_version: Literal["ovk.guarantee_manifest.v1"] = (
        "ovk.guarantee_manifest.v1"
    )
    guarantees: list[GuaranteeSpec] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_graph(self) -> "GuaranteeManifest":
        by_id: dict[str, GuaranteeSpec] = {}
        for spec in self.guarantees:
            if spec.guarantee_id in by_id:
                raise ValueError(f"duplicate guarantee_id: {spec.guarantee_id}")
            by_id[spec.guarantee_id] = spec

        for spec in self.guarantees:
            missing = sorted(
                dependency
                for dependency in spec.dependencies
                if dependency not in by_id
            )
            if missing:
                raise ValueError(
                    f"guarantee {spec.guarantee_id} references unknown "
                    f"dependencies: {', '.join(missing)}"
                )

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(guarantee_id: str) -> None:
            if guarantee_id in visited:
                return
            if guarantee_id in visiting:
                raise ValueError(
                    f"guarantee dependency cycle includes: {guarantee_id}"
                )
            visiting.add(guarantee_id)
            for dependency in by_id[guarantee_id].dependencies:
                visit(dependency)
            visiting.remove(guarantee_id)
            visited.add(guarantee_id)

        for guarantee_id in sorted(by_id):
            visit(guarantee_id)
        return self

    def canonical_payload(self) -> dict[str, Any]:
        """Return order-stable semantic content for manifest identity."""

        guarantees: list[dict[str, Any]] = []
        for spec in sorted(self.guarantees, key=lambda item: item.guarantee_id):
            payload = spec.model_dump(mode="json")
            payload["assumptions"] = sorted(payload.get("assumptions") or [])
            payload["dependencies"] = sorted(payload.get("dependencies") or [])
            guarantees.append(payload)
        return {
            "schema_version": self.schema_version,
            "guarantees": guarantees,
        }

    @property
    def manifest_digest(self) -> str:
        return content_digest(self.canonical_payload())

    def by_id(self) -> dict[str, GuaranteeSpec]:
        return {item.guarantee_id: item for item in self.guarantees}


class GuaranteeDefinitionChange(BaseModel):
    """Field-level diff for one durable guarantee definition."""

    guarantee_id: str
    base_definition_digest: str
    head_definition_digest: str
    spec_version_changed: bool = False
    machine_claim_changed: bool = False
    statement_changed: bool = False
    assumptions_changed: bool = False
    dependencies_changed: bool = False
    origin_intent_changed: bool = False
    changed_fields: list[str] = Field(default_factory=list)


class GuaranteeManifestDiff(BaseModel):
    """Canonical semantic diff between trusted base and proposed head manifests."""

    base_manifest_digest: str
    head_manifest_digest: str
    added_guarantee_ids: list[str] = Field(default_factory=list)
    removed_guarantee_ids: list[str] = Field(default_factory=list)
    modified_guarantees: list[GuaranteeDefinitionChange] = Field(
        default_factory=list
    )
    unchanged_guarantee_ids: list[str] = Field(default_factory=list)

    @property
    def semantic_change(self) -> bool:
        return bool(
            self.added_guarantee_ids
            or self.removed_guarantee_ids
            or self.modified_guarantees
        )


class GovernedGuaranteeContext(BaseModel):
    """Trusted active guarantees plus the workspace/head proposal."""

    repository_path: str = GUARANTEE_MANIFEST_REPOSITORY_PATH
    base_sha: str | None = None

    active_source: Literal[
        "workspace_local",
        "base_revision",
        "base_absent",
        "unavailable",
    ]
    active_manifest: GuaranteeManifest | None = None
    active_revision: str | None = None
    assurance_target_available: bool

    proposed_manifest: GuaranteeManifest | None = None
    proposal_valid: bool
    proposal_error: str | None = None

    manifest_path_touched: bool = False
    semantic_manifest_changed: bool | None = None
    change_detection_mismatch: bool = False
    governance_review_required: bool = False
    diff: GuaranteeManifestDiff | None = None
    warning: str | None = None

    def require_assurance_specs(self) -> list[GuaranteeSpec]:
        """Return trusted assurance targets or fail closed."""

        if not self.assurance_target_available or self.active_manifest is None:
            raise ValueError("trusted guarantee assurance target is unavailable")
        return list(self.active_manifest.guarantees)

    def proposed_specs(self) -> list[GuaranteeSpec] | None:
        if not self.proposal_valid or self.proposed_manifest is None:
            return None
        return list(self.proposed_manifest.guarantees)


def _validate_manifest_mapping(
    loaded: object,
    *,
    source: str,
) -> GuaranteeManifest:
    if not isinstance(loaded, dict):
        raise ValueError(
            f"OVK guarantee manifest from {source} must contain a JSON object"
        )
    manifest_schema_path = schema_path("guarantee.manifest.schema.json")
    if not manifest_schema_path.exists():
        raise ValueError(
            f"OVK guarantee manifest schema is missing: {manifest_schema_path}"
        )
    require_schema_valid(
        loaded,
        load_json(manifest_schema_path),
        context=f"OVK guarantee manifest from {source}",
    )
    try:
        return GuaranteeManifest.model_validate(loaded)
    except Exception as error:
        raise ValueError(
            f"OVK guarantee manifest from {source} failed typed validation: "
            f"{error}"
        ) from error


def parse_guarantee_manifest_text(
    text: str,
    *,
    source: str,
) -> GuaranteeManifest:
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"invalid OVK guarantee manifest JSON from {source}: {error}"
        ) from error
    return _validate_manifest_mapping(loaded, source=source)


def load_guarantee_manifest(
    manifest_path: Path = Path(GUARANTEE_MANIFEST_REPOSITORY_PATH),
) -> GuaranteeManifest:
    """Load workspace manifest; absence means no declared guarantees."""

    if not manifest_path.exists():
        return GuaranteeManifest()
    return parse_guarantee_manifest_text(
        manifest_path.read_text(encoding="utf-8"),
        source=str(manifest_path),
    )


def _repository_path_matches(
    changed_files: list[str],
    target: Path,
) -> bool:
    absolute_target = target.as_posix().lstrip("./")
    relative_target = GUARANTEE_MANIFEST_REPOSITORY_PATH.lstrip("./")
    for path in changed_files:
        normalized = str(path).replace("\\", "/").lstrip("./")
        if normalized in {absolute_target, relative_target}:
            return True
        if normalized.endswith("/" + relative_target):
            return True
    return False


def _run_git(args: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _load_base_manifest(
    *,
    base_sha: str,
    manifest_path: Path,
) -> tuple[
    Literal["base_revision", "base_absent", "unavailable"],
    GuaranteeManifest | None,
    str | None,
]:
    """Load exact base manifest while distinguishing absence from unavailability."""

    commit_check = _run_git(
        ["git", "cat-file", "-e", f"{base_sha}^{{commit}}"]
    )
    if commit_check is None or commit_check.returncode != 0:
        return (
            "unavailable",
            None,
            "base revision is unavailable for guarantee governance",
        )

    repository_path = manifest_path.as_posix()
    path_check = _run_git(
        ["git", "cat-file", "-e", f"{base_sha}:{repository_path}"]
    )
    if path_check is None:
        return (
            "unavailable",
            None,
            "could not determine whether the base guarantee manifest exists",
        )
    if path_check.returncode != 0:
        return "base_absent", GuaranteeManifest(), None

    completed = _run_git(
        ["git", "show", f"{base_sha}:{repository_path}"]
    )
    if completed is None or completed.returncode != 0:
        return (
            "unavailable",
            None,
            "base guarantee manifest exists but could not be read",
        )

    try:
        manifest = parse_guarantee_manifest_text(
            completed.stdout,
            source=f"base revision {base_sha}:{repository_path}",
        )
    except ValueError as error:
        return (
            "unavailable",
            None,
            f"base guarantee manifest is invalid: {error}",
        )
    return "base_revision", manifest, None


def _definition_change(
    base: GuaranteeSpec,
    head: GuaranteeSpec,
) -> GuaranteeDefinitionChange | None:
    changed_fields: list[str] = []

    spec_version_changed = base.spec_version != head.spec_version
    if spec_version_changed:
        changed_fields.append("spec_version")

    machine_claim_changed = (
        base.guarantee_type != head.guarantee_type
        or base.selector != head.selector
    )
    if machine_claim_changed:
        changed_fields.append("machine_claim")

    statement_changed = base.statement != head.statement
    if statement_changed:
        changed_fields.append("statement")

    assumptions_changed = sorted(base.assumptions) != sorted(head.assumptions)
    if assumptions_changed:
        changed_fields.append("assumptions")

    dependencies_changed = sorted(base.dependencies) != sorted(head.dependencies)
    if dependencies_changed:
        changed_fields.append("dependencies")

    origin_intent_changed = base.origin_intent != head.origin_intent
    if origin_intent_changed:
        changed_fields.append("origin_intent")

    if not changed_fields:
        return None

    return GuaranteeDefinitionChange(
        guarantee_id=base.guarantee_id,
        base_definition_digest=base.definition_digest,
        head_definition_digest=head.definition_digest,
        spec_version_changed=spec_version_changed,
        machine_claim_changed=machine_claim_changed,
        statement_changed=statement_changed,
        assumptions_changed=assumptions_changed,
        dependencies_changed=dependencies_changed,
        origin_intent_changed=origin_intent_changed,
        changed_fields=changed_fields,
    )


def diff_guarantee_manifests(
    base: GuaranteeManifest,
    head: GuaranteeManifest,
) -> GuaranteeManifestDiff:
    """Compute an order-stable semantic Guarantee Diff."""

    base_by_id = base.by_id()
    head_by_id = head.by_id()
    base_ids = set(base_by_id)
    head_ids = set(head_by_id)

    added = sorted(head_ids - base_ids)
    removed = sorted(base_ids - head_ids)
    modified: list[GuaranteeDefinitionChange] = []
    unchanged: list[str] = []

    for guarantee_id in sorted(base_ids & head_ids):
        change = _definition_change(
            base_by_id[guarantee_id],
            head_by_id[guarantee_id],
        )
        if change is None:
            unchanged.append(guarantee_id)
        else:
            modified.append(change)

    return GuaranteeManifestDiff(
        base_manifest_digest=base.manifest_digest,
        head_manifest_digest=head.manifest_digest,
        added_guarantee_ids=added,
        removed_guarantee_ids=removed,
        modified_guarantees=modified,
        unchanged_guarantee_ids=unchanged,
    )


def load_governed_guarantee_context(
    *,
    changed_files: list[str],
    base_sha: str | None,
    manifest_path: Path = Path(GUARANTEE_MANIFEST_REPOSITORY_PATH),
) -> GovernedGuaranteeContext:
    """Load trusted active guarantees and a separately governed head proposal.

    With a base SHA, the base manifest is always the active assurance target.
    Changed-files metadata is retained only to detect/report inconsistency.
    """

    touched = _repository_path_matches(changed_files, manifest_path)

    try:
        proposed = load_guarantee_manifest(manifest_path)
        proposal_valid = True
        proposal_error = None
    except ValueError as error:
        proposed = None
        proposal_valid = False
        proposal_error = str(error)

    if base_sha is None:
        if not proposal_valid or proposed is None:
            return GovernedGuaranteeContext(
                base_sha=None,
                active_source="unavailable",
                active_manifest=None,
                assurance_target_available=False,
                proposed_manifest=None,
                proposal_valid=False,
                proposal_error=proposal_error,
                manifest_path_touched=touched,
                semantic_manifest_changed=None,
                governance_review_required=True,
                warning=(
                    "local guarantee manifest is invalid; no trusted assurance "
                    "target is available"
                ),
            )
        return GovernedGuaranteeContext(
            base_sha=None,
            active_source="workspace_local",
            active_manifest=proposed,
            assurance_target_available=True,
            proposed_manifest=proposed,
            proposal_valid=True,
            manifest_path_touched=touched,
            semantic_manifest_changed=False,
            governance_review_required=touched,
            diff=diff_guarantee_manifests(proposed, proposed),
        )

    active_source, active, base_warning = _load_base_manifest(
        base_sha=base_sha,
        manifest_path=manifest_path,
    )
    if active is None:
        return GovernedGuaranteeContext(
            base_sha=base_sha,
            active_source="unavailable",
            active_manifest=None,
            active_revision=base_sha,
            assurance_target_available=False,
            proposed_manifest=proposed,
            proposal_valid=proposal_valid,
            proposal_error=proposal_error,
            manifest_path_touched=touched,
            semantic_manifest_changed=None,
            governance_review_required=True,
            warning=base_warning,
        )

    if not proposal_valid or proposed is None:
        return GovernedGuaranteeContext(
            base_sha=base_sha,
            active_source=active_source,
            active_manifest=active,
            active_revision=base_sha,
            assurance_target_available=True,
            proposed_manifest=None,
            proposal_valid=False,
            proposal_error=proposal_error,
            manifest_path_touched=touched,
            semantic_manifest_changed=True,
            governance_review_required=True,
            warning=(
                "head guarantee proposal is invalid; trusted base guarantees "
                "remain the assurance target"
            ),
        )

    diff = diff_guarantee_manifests(active, proposed)
    semantic_changed = diff.semantic_change
    metadata_mismatch = semantic_changed and not touched

    warning = base_warning
    if metadata_mismatch:
        warning = (
            "base/head guarantee manifests differ although changed-files "
            "metadata does not list the guarantee manifest"
        )

    return GovernedGuaranteeContext(
        base_sha=base_sha,
        active_source=active_source,
        active_manifest=active,
        active_revision=base_sha,
        assurance_target_available=True,
        proposed_manifest=proposed,
        proposal_valid=True,
        manifest_path_touched=touched,
        semantic_manifest_changed=semantic_changed,
        change_detection_mismatch=metadata_mismatch,
        governance_review_required=(touched or semantic_changed),
        diff=diff,
        warning=warning,
    )


def guarantee_governance_summary(
    context: GovernedGuaranteeContext,
) -> dict[str, Any]:
    """Return compact machine-readable governance metadata for check outputs."""

    diff_payload = (
        context.diff.model_dump(mode="json")
        if context.diff is not None
        else None
    )
    return {
        "repository_path": context.repository_path,
        "base_sha": context.base_sha,
        "active_source": context.active_source,
        "active_revision": context.active_revision,
        "assurance_target_available": context.assurance_target_available,
        "active_manifest_digest": (
            context.active_manifest.manifest_digest
            if context.active_manifest is not None
            else None
        ),
        "proposed_manifest_digest": (
            context.proposed_manifest.manifest_digest
            if context.proposed_manifest is not None
            else None
        ),
        "proposal_valid": context.proposal_valid,
        "proposal_error": context.proposal_error,
        "manifest_path_touched": context.manifest_path_touched,
        "semantic_manifest_changed": context.semantic_manifest_changed,
        "change_detection_mismatch": context.change_detection_mismatch,
        "governance_review_required": context.governance_review_required,
        "warning": context.warning,
        "diff_semantic_change": (
            context.diff.semantic_change
            if context.diff is not None
            else None
        ),
        "diff": diff_payload,
    }
