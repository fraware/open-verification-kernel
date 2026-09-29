"""Pull-request review artifact joining code, guarantee, and assurance diffs.

This module is a projection layer only. It does not alter OVK merge authority.

The central trust rule is enforced explicitly: both base and head assurance
snapshots used in a pull-request review must have been evaluated against the
trusted active guarantee definitions from the base manifest. A head snapshot
built against the pull request's proposed guarantee definitions is rejected.

This yields three distinct views:
- Code Diff: repository files changed by the pull request.
- Guarantee Diff: proposed governance changes to the durable guarantee manifest.
- Assurance Diff: state transitions of the trusted base guarantees under the
  base and head software revisions.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ovk.core.bundle import content_digest
from ovk.core.guarantee_assurance_ledger import (
    GuaranteeAssuranceDelta,
    compute_guarantee_assurance_deltas,
    compute_guarantee_assurance_snapshot_digest,
    validate_guarantee_assurance_snapshot_structure,
)
from ovk.core.guarantee_assurance_state import GuaranteeAssuranceSnapshot
from ovk.core.guarantee_manifest import (
    GovernedGuaranteeContext,
    GuaranteeManifestDiff,
)


PR_ASSURANCE_REVIEW_SCHEMA_VERSION = "ovk.pr_assurance_review.v1"


class CodeDiffReview(BaseModel):
    """Normalized repository file-change view."""

    changed_files: list[str] = Field(default_factory=list)
    changed_file_count: int = Field(ge=0)


class GuaranteeDiffReview(BaseModel):
    """Governed base/head guarantee-manifest view."""

    active_source: str
    active_revision: str | None = None
    assurance_target_available: bool
    active_manifest_digest: str | None = None
    proposed_manifest_digest: str | None = None
    proposal_valid: bool
    governance_review_required: bool
    manifest_path_touched: bool
    semantic_manifest_changed: bool | None = None
    change_detection_mismatch: bool = False
    warning: str | None = None
    proposal_error: str | None = None
    diff: GuaranteeManifestDiff | None = None


class AssuranceDiffReview(BaseModel):
    """Base-to-head transition of trusted guarantee assurance state."""

    available: bool
    reason_codes: list[str] = Field(default_factory=list)
    base_snapshot_digest: str | None = None
    head_snapshot_digest: str | None = None
    deltas: list[GuaranteeAssuranceDelta] = Field(default_factory=list)
    freshly_established_guarantee_ids: list[str] = Field(default_factory=list)
    reused_established_guarantee_ids: list[str] = Field(default_factory=list)
    assurance_lost_guarantee_ids: list[str] = Field(default_factory=list)
    violated_guarantee_ids: list[str] = Field(default_factory=list)
    open_guarantee_ids: list[str] = Field(default_factory=list)


class PullRequestAssuranceReview(BaseModel):
    """Machine-readable Code Diff + Guarantee Diff + Assurance Diff."""

    schema_version: Literal["ovk.pr_assurance_review.v1"] = (
        "ovk.pr_assurance_review.v1"
    )
    review_id: str
    review_digest: str
    repo: str
    base_sha: str
    head_sha: str
    code_diff: CodeDiffReview
    guarantee_diff: GuaranteeDiffReview
    assurance_diff: AssuranceDiffReview


def _expected_definition_digests(
    governance: GovernedGuaranteeContext,
) -> dict[str, str] | None:
    if not governance.assurance_target_available:
        return None
    manifest = governance.active_manifest
    if manifest is None:
        return None
    return {
        spec.guarantee_id: spec.definition_digest
        for spec in manifest.guarantees
    }


def _validate_snapshot(
    snapshot: GuaranteeAssuranceSnapshot,
    *,
    role: Literal["base", "head"],
    repo: str,
    base_sha: str,
    head_sha: str,
    expected_definition_digests: dict[str, str],
) -> None:
    issues = validate_guarantee_assurance_snapshot_structure(snapshot)
    if issues:
        raise ValueError(
            f"{role} guarantee assurance snapshot is structurally invalid: "
            + ", ".join(issues)
        )

    if snapshot.subject_repo != repo:
        raise ValueError(
            f"{role} snapshot repository does not match pull-request repository"
        )

    expected_head = base_sha if role == "base" else head_sha
    if snapshot.subject_head_sha != expected_head:
        raise ValueError(
            f"{role} snapshot head SHA does not match expected revision"
        )

    if role == "head" and snapshot.subject_base_sha != base_sha:
        raise ValueError(
            "head snapshot base SHA does not match pull-request base revision"
        )

    if snapshot.graph.spec_definition_digests != expected_definition_digests:
        raise ValueError(
            f"{role} snapshot was not evaluated against the trusted active "
            "base guarantee definitions"
        )


def _guarantee_diff_view(
    governance: GovernedGuaranteeContext,
) -> GuaranteeDiffReview:
    active_digest = (
        governance.active_manifest.manifest_digest
        if governance.active_manifest is not None
        else None
    )
    proposed_digest = (
        governance.proposed_manifest.manifest_digest
        if governance.proposed_manifest is not None
        else None
    )
    return GuaranteeDiffReview(
        active_source=governance.active_source,
        active_revision=governance.active_revision,
        assurance_target_available=governance.assurance_target_available,
        active_manifest_digest=active_digest,
        proposed_manifest_digest=proposed_digest,
        proposal_valid=governance.proposal_valid,
        governance_review_required=governance.governance_review_required,
        manifest_path_touched=governance.manifest_path_touched,
        semantic_manifest_changed=governance.semantic_manifest_changed,
        change_detection_mismatch=governance.change_detection_mismatch,
        warning=governance.warning,
        proposal_error=governance.proposal_error,
        diff=governance.diff,
    )


def _assurance_diff_view(
    *,
    governance: GovernedGuaranteeContext,
    repo: str,
    base_sha: str,
    head_sha: str,
    base_snapshot: GuaranteeAssuranceSnapshot | None,
    head_snapshot: GuaranteeAssuranceSnapshot | None,
) -> AssuranceDiffReview:
    expected = _expected_definition_digests(governance)
    reasons: list[str] = []

    if expected is None:
        reasons.append("trusted_assurance_target_unavailable")
    if base_snapshot is None:
        reasons.append("base_snapshot_missing")
    if head_snapshot is None:
        reasons.append("head_snapshot_missing")

    if reasons:
        return AssuranceDiffReview(
            available=False,
            reason_codes=sorted(set(reasons)),
        )

    assert base_snapshot is not None
    assert head_snapshot is not None
    assert expected is not None

    _validate_snapshot(
        base_snapshot,
        role="base",
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        expected_definition_digests=expected,
    )
    _validate_snapshot(
        head_snapshot,
        role="head",
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        expected_definition_digests=expected,
    )

    if base_snapshot.policy_digest != head_snapshot.policy_digest:
        raise ValueError(
            "base and head assurance snapshots use different policy digests"
        )

    deltas = compute_guarantee_assurance_deltas(
        base_snapshot,
        head_snapshot,
    )

    fresh = sorted(
        delta.guarantee_id
        for delta in deltas
        if delta.head_status == "established"
        and delta.head_evidence_origin == "fresh"
    )
    reused = sorted(
        delta.guarantee_id
        for delta in deltas
        if delta.head_status == "established"
        and delta.head_evidence_origin == "reused"
    )
    lost = sorted(
        delta.guarantee_id
        for delta in deltas
        if delta.kind == "assurance_lost"
    )
    violated = sorted(
        delta.guarantee_id
        for delta in deltas
        if delta.head_status == "violated"
    )
    open_guarantees = sorted(
        delta.guarantee_id
        for delta in deltas
        if delta.head_status is not None
        and delta.head_status != "established"
    )

    return AssuranceDiffReview(
        available=True,
        base_snapshot_digest=compute_guarantee_assurance_snapshot_digest(
            base_snapshot
        ),
        head_snapshot_digest=compute_guarantee_assurance_snapshot_digest(
            head_snapshot
        ),
        deltas=deltas,
        freshly_established_guarantee_ids=fresh,
        reused_established_guarantee_ids=reused,
        assurance_lost_guarantee_ids=lost,
        violated_guarantee_ids=violated,
        open_guarantee_ids=open_guarantees,
    )


def _review_digest_payload(
    *,
    repo: str,
    base_sha: str,
    head_sha: str,
    code_diff: CodeDiffReview,
    guarantee_diff: GuaranteeDiffReview,
    assurance_diff: AssuranceDiffReview,
) -> dict:
    return {
        "schema_version": PR_ASSURANCE_REVIEW_SCHEMA_VERSION,
        "repo": repo,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "code_diff": code_diff.model_dump(mode="json"),
        "guarantee_diff": guarantee_diff.model_dump(mode="json"),
        "assurance_diff": assurance_diff.model_dump(mode="json"),
    }


def build_pull_request_assurance_review(
    *,
    repo: str,
    base_sha: str,
    head_sha: str,
    changed_files: list[str],
    governance: GovernedGuaranteeContext,
    base_snapshot: GuaranteeAssuranceSnapshot | None = None,
    head_snapshot: GuaranteeAssuranceSnapshot | None = None,
) -> PullRequestAssuranceReview:
    """Build one content-addressed three-diff review artifact."""

    repo = repo.strip()
    base_sha = base_sha.strip()
    head_sha = head_sha.strip()
    if not repo or not base_sha or not head_sha:
        raise ValueError("repo, base_sha, and head_sha must be non-empty")

    if governance.base_sha is not None and governance.base_sha != base_sha:
        raise ValueError(
            "governed guarantee context base SHA does not match review base SHA"
        )

    normalized_files = sorted(
        {
            str(path).replace("\\", "/")
            for path in changed_files
            if str(path).strip()
        }
    )
    code_diff = CodeDiffReview(
        changed_files=normalized_files,
        changed_file_count=len(normalized_files),
    )
    guarantee_diff = _guarantee_diff_view(governance)
    assurance_diff = _assurance_diff_view(
        governance=governance,
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        base_snapshot=base_snapshot,
        head_snapshot=head_snapshot,
    )

    payload = _review_digest_payload(
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        code_diff=code_diff,
        guarantee_diff=guarantee_diff,
        assurance_diff=assurance_diff,
    )
    digest = content_digest(payload)
    return PullRequestAssuranceReview(
        review_id=f"pr-assurance-{digest[:20]}",
        review_digest=digest,
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        code_diff=code_diff,
        guarantee_diff=guarantee_diff,
        assurance_diff=assurance_diff,
    )


def render_pull_request_assurance_review_markdown(
    review: PullRequestAssuranceReview,
) -> str:
    """Render the three-diff review as concise pull-request Markdown."""

    lines = [
        "## OVK Pull Request Assurance Review",
        "",
        f"Repository: `{review.repo}`",
        f"Base: `{review.base_sha}`",
        f"Head: `{review.head_sha}`",
        "",
        "### Code Diff",
        "",
        f"Changed files: {review.code_diff.changed_file_count}",
    ]
    for path in review.code_diff.changed_files[:20]:
        lines.append(f"- `{path}`")
    if len(review.code_diff.changed_files) > 20:
        lines.append(
            f"- ... {len(review.code_diff.changed_files) - 20} additional files"
        )

    gd = review.guarantee_diff
    lines.extend(
        [
            "",
            "### Guarantee Diff",
            "",
            f"Active source: `{gd.active_source}`",
            f"Governance review required: `{gd.governance_review_required}`",
        ]
    )
    if not gd.proposal_valid:
        lines.append("Proposed manifest: `invalid`")
        if gd.proposal_error:
            lines.append(gd.proposal_error)
    elif gd.diff is None or not gd.diff.semantic_change:
        lines.append("No semantic guarantee-manifest change.")
    else:
        if gd.diff.added_guarantee_ids:
            lines.append(
                "Added: "
                + ", ".join(
                    f"`{item}`" for item in gd.diff.added_guarantee_ids
                )
            )
        if gd.diff.removed_guarantee_ids:
            lines.append(
                "Removed: "
                + ", ".join(
                    f"`{item}`" for item in gd.diff.removed_guarantee_ids
                )
            )
        for change in gd.diff.modified_guarantees:
            fields = ", ".join(change.changed_fields)
            lines.append(
                f"- `{change.guarantee_id}` modified: "
                f"{fields or 'definition changed'}"
            )

    ad = review.assurance_diff
    lines.extend(["", "### Assurance Diff", ""])
    if not ad.available:
        lines.append(
            "Assurance diff unavailable: "
            + ", ".join(ad.reason_codes)
        )
    elif not ad.deltas:
        lines.append("No active guarantees.")
    else:
        for delta in ad.deltas:
            origin = (
                f", evidence={delta.head_evidence_origin}"
                if delta.head_evidence_origin is not None
                else ""
            )
            lines.append(
                f"- `{delta.guarantee_id}`: "
                f"`{delta.base_status}` -> `{delta.head_status}` "
                f"(`{delta.kind}`{origin})"
            )

    lines.extend(
        [
            "",
            (
                "The Guarantee Diff describes proposed governance changes. "
                "The Assurance Diff is evaluated against the trusted base "
                "guarantee definitions. This review does not change OVK merge "
                "decision authority."
            ),
        ]
    )
    return "\n".join(lines) + "\n"
