"""Durable intent state, semantic diffs, and external approval evidence.

Intent content is repository/PR-controlled input. Approval is a separate object
bound to the exact intent-diff digest and commit SHA. No field inside an
IntentRecord or AssuranceClaim is authoritative approval.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ovk.core.bundle import content_digest
from ovk.core.models import VerificationSubject


IntentOrigin = Literal["human", "policy", "repository", "imported", "ai_candidate"]
IntentChangeKind = Literal["added", "removed", "modified"]
ApprovalSource = Literal["github_review", "policy", "external_authority"]

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")


def _stable_id(value: str) -> str:
    value = value.strip()
    if not _ID_RE.fullmatch(value):
        raise ValueError("intent identifiers must be stable non-empty identifiers")
    return value


class IntentRecord(BaseModel):
    """One semantic intent declaration.

    The record deliberately has no approval field. Origin describes where the
    content came from; it does not authorize the content.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["ovk.intent.v1"] = "ovk.intent.v1"
    intent_id: str
    intent_kind: str
    title: str
    statement: str
    payload: dict[str, Any] = Field(default_factory=dict)
    owner_refs: list[str] = Field(default_factory=list)
    origin: IntentOrigin = "repository"
    source_refs: list[str] = Field(default_factory=list)

    _validate_id = field_validator("intent_id")(_stable_id)

    @field_validator("intent_kind", "title", "statement")
    @classmethod
    def non_empty_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("intent text fields must be non-empty")
        return value


class IntentSnapshot(BaseModel):
    """Intent corpus at one immutable repository revision."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["ovk.intent_snapshot.v1"] = "ovk.intent_snapshot.v1"
    repo: str
    revision_sha: str
    intents: list[IntentRecord] = Field(default_factory=list)
    snapshot_digest: str | None = None

    @model_validator(mode="after")
    def identity_is_valid(self) -> "IntentSnapshot":
        ids = [item.intent_id for item in self.intents]
        duplicates = sorted({item for item in ids if ids.count(item) > 1})
        if duplicates:
            raise ValueError(f"duplicate intent ids: {', '.join(duplicates)}")
        if self.snapshot_digest is not None and self.snapshot_digest != compute_intent_snapshot_digest(self):
            raise ValueError("snapshot_digest does not match canonical intent snapshot contents")
        return self


class IntentChange(BaseModel):
    """One semantic intent change, carrying before/after content for review."""

    model_config = ConfigDict(extra="forbid")

    change_id: str
    change_kind: IntentChangeKind
    intent_id: str
    before: IntentRecord | None = None
    after: IntentRecord | None = None
    before_digest: str | None = None
    after_digest: str | None = None

    _validate_ids = field_validator("change_id", "intent_id")(_stable_id)

    @model_validator(mode="after")
    def shape_matches_change_kind(self) -> "IntentChange":
        if self.change_kind == "added" and (self.before is not None or self.after is None):
            raise ValueError("added intent change requires after and forbids before")
        if self.change_kind == "removed" and (self.before is None or self.after is not None):
            raise ValueError("removed intent change requires before and forbids after")
        if self.change_kind == "modified" and (self.before is None or self.after is None):
            raise ValueError("modified intent change requires before and after")
        for record in (self.before, self.after):
            if record is not None and record.intent_id != self.intent_id:
                raise ValueError("intent change record identity does not match intent_id")

        expected_before = compute_intent_record_digest(self.before) if self.before is not None else None
        expected_after = compute_intent_record_digest(self.after) if self.after is not None else None
        if self.before_digest != expected_before:
            raise ValueError("before_digest does not match before intent")
        if self.after_digest != expected_after:
            raise ValueError("after_digest does not match after intent")
        expected_change_id = compute_intent_change_id(
            self.change_kind,
            self.intent_id,
            expected_before,
            expected_after,
        )
        if self.change_id != expected_change_id:
            raise ValueError("change_id does not match canonical intent change identity")
        return self


class IntentDiff(BaseModel):
    """Semantic intent delta bound to a base/head repository transition."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["ovk.intent_diff.v1"] = "ovk.intent_diff.v1"
    subject: VerificationSubject
    base_snapshot_digest: str
    head_snapshot_digest: str
    changes: list[IntentChange] = Field(default_factory=list)
    diff_digest: str | None = None

    @model_validator(mode="after")
    def identity_is_valid(self) -> "IntentDiff":
        ids = [item.change_id for item in self.changes]
        duplicates = sorted({item for item in ids if ids.count(item) > 1})
        if duplicates:
            raise ValueError(f"duplicate intent change ids: {', '.join(duplicates)}")
        if self.diff_digest is not None and self.diff_digest != compute_intent_diff_digest(self):
            raise ValueError("diff_digest does not match canonical intent diff contents")
        return self


class ApprovalAuthority(BaseModel):
    """External authority that approved an intent delta."""

    model_config = ConfigDict(extra="forbid")

    source: ApprovalSource
    authority_id: str
    evidence_ref: str
    authority_context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("authority_id", "evidence_ref")
    @classmethod
    def non_empty_authority_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("approval authority fields must be non-empty")
        return value


class IntentApprovalEvidence(BaseModel):
    """Approval evidence external to repository-controlled intent content.

    Authenticity of the authority/evidence_ref is established by the integration
    producing this object, not by fields authored in the PR branch.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["ovk.intent_approval.v1"] = "ovk.intent_approval.v1"
    subject: VerificationSubject
    intent_diff_digest: str
    approved_change_ids: list[str]
    authority: ApprovalAuthority
    policy_ref: str
    approval_digest: str | None = None

    @field_validator("approved_change_ids")
    @classmethod
    def approval_ids_are_unique(cls, values: list[str]) -> list[str]:
        normalized = [_stable_id(value) for value in values]
        if len(set(normalized)) != len(normalized):
            raise ValueError("approved_change_ids must be unique")
        if not normalized:
            raise ValueError("approval evidence must approve at least one change")
        return normalized

    @field_validator("policy_ref")
    @classmethod
    def policy_ref_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("policy_ref must be non-empty")
        return value

    @model_validator(mode="after")
    def digest_matches(self) -> "IntentApprovalEvidence":
        if self.approval_digest is not None and self.approval_digest != compute_intent_approval_digest(self):
            raise ValueError("approval_digest does not match canonical approval evidence")
        return self


def intent_record_digest_input(record: IntentRecord) -> dict[str, Any]:
    payload = record.model_dump(mode="json")
    payload["owner_refs"] = sorted(payload["owner_refs"])
    payload["source_refs"] = sorted(payload["source_refs"])
    return payload


def compute_intent_record_digest(record: IntentRecord) -> str:
    return content_digest(intent_record_digest_input(record))


def intent_snapshot_digest_input(snapshot: IntentSnapshot) -> dict[str, Any]:
    return {
        "schema_version": snapshot.schema_version,
        "repo": snapshot.repo,
        "revision_sha": snapshot.revision_sha,
        "intents": [
            intent_record_digest_input(item)
            for item in sorted(snapshot.intents, key=lambda value: value.intent_id)
        ],
    }


def compute_intent_snapshot_digest(snapshot: IntentSnapshot) -> str:
    return content_digest(intent_snapshot_digest_input(snapshot))


def seal_intent_snapshot(snapshot: IntentSnapshot) -> IntentSnapshot:
    return snapshot.model_copy(update={"snapshot_digest": compute_intent_snapshot_digest(snapshot)})


def compute_intent_change_id(
    change_kind: IntentChangeKind,
    intent_id: str,
    before_digest: str | None,
    after_digest: str | None,
) -> str:
    fingerprint = content_digest(
        {
            "change_kind": change_kind,
            "intent_id": intent_id,
            "before_digest": before_digest,
            "after_digest": after_digest,
        }
    )[:20]
    return f"intent-change.{fingerprint}"


def _make_change(
    change_kind: IntentChangeKind,
    intent_id: str,
    before: IntentRecord | None,
    after: IntentRecord | None,
) -> IntentChange:
    before_digest = compute_intent_record_digest(before) if before is not None else None
    after_digest = compute_intent_record_digest(after) if after is not None else None
    return IntentChange(
        change_id=compute_intent_change_id(change_kind, intent_id, before_digest, after_digest),
        change_kind=change_kind,
        intent_id=intent_id,
        before=before,
        after=after,
        before_digest=before_digest,
        after_digest=after_digest,
    )


def compute_intent_diff(
    base: IntentSnapshot,
    head: IntentSnapshot,
    *,
    subject: VerificationSubject,
) -> IntentDiff:
    """Compute an exact semantic diff between two intent snapshots."""

    if base.repo != head.repo or base.repo != subject.repo:
        raise ValueError("intent snapshot repository does not match diff subject")
    if subject.base_sha is None:
        raise ValueError("intent diff subject requires base_sha")
    if base.revision_sha != subject.base_sha:
        raise ValueError("base intent snapshot revision does not match subject.base_sha")
    if head.revision_sha != subject.head_sha:
        raise ValueError("head intent snapshot revision does not match subject.head_sha")

    base_by_id = {item.intent_id: item for item in base.intents}
    head_by_id = {item.intent_id: item for item in head.intents}
    changes: list[IntentChange] = []

    for intent_id in sorted(set(base_by_id) | set(head_by_id)):
        before = base_by_id.get(intent_id)
        after = head_by_id.get(intent_id)
        if before is None and after is not None:
            changes.append(_make_change("added", intent_id, None, after))
        elif before is not None and after is None:
            changes.append(_make_change("removed", intent_id, before, None))
        elif before is not None and after is not None:
            if compute_intent_record_digest(before) != compute_intent_record_digest(after):
                changes.append(_make_change("modified", intent_id, before, after))

    provisional = IntentDiff(
        subject=subject,
        base_snapshot_digest=compute_intent_snapshot_digest(base),
        head_snapshot_digest=compute_intent_snapshot_digest(head),
        changes=changes,
    )
    return provisional.model_copy(update={"diff_digest": compute_intent_diff_digest(provisional)})


def intent_diff_digest_input(diff: IntentDiff) -> dict[str, Any]:
    return {
        "schema_version": diff.schema_version,
        "subject": diff.subject.model_dump(mode="json"),
        "base_snapshot_digest": diff.base_snapshot_digest,
        "head_snapshot_digest": diff.head_snapshot_digest,
        "changes": [
            item.model_dump(mode="json")
            for item in sorted(diff.changes, key=lambda value: value.change_id)
        ],
    }


def compute_intent_diff_digest(diff: IntentDiff) -> str:
    return content_digest(intent_diff_digest_input(diff))


def intent_approval_digest_input(approval: IntentApprovalEvidence) -> dict[str, Any]:
    payload = approval.model_dump(mode="json", exclude={"approval_digest"})
    payload["approved_change_ids"] = sorted(payload["approved_change_ids"])
    return payload


def compute_intent_approval_digest(approval: IntentApprovalEvidence) -> str:
    return content_digest(intent_approval_digest_input(approval))


def create_intent_approval(
    diff: IntentDiff,
    *,
    approved_change_ids: list[str],
    authority: ApprovalAuthority,
    policy_ref: str,
) -> IntentApprovalEvidence:
    known = {item.change_id for item in diff.changes}
    unknown = sorted(set(approved_change_ids) - known)
    if unknown:
        raise ValueError(f"approval references unknown intent changes: {', '.join(unknown)}")
    if diff.diff_digest is None:
        diff = diff.model_copy(update={"diff_digest": compute_intent_diff_digest(diff)})
    provisional = IntentApprovalEvidence(
        subject=diff.subject,
        intent_diff_digest=diff.diff_digest,
        approved_change_ids=approved_change_ids,
        authority=authority,
        policy_ref=policy_ref,
    )
    return provisional.model_copy(update={"approval_digest": compute_intent_approval_digest(provisional)})


def verify_intent_approval(diff: IntentDiff, approval: IntentApprovalEvidence) -> list[str]:
    """Return integrity/binding issues for approval evidence."""

    issues: list[str] = []
    expected_diff_digest = compute_intent_diff_digest(diff)
    if approval.subject != diff.subject:
        issues.append("approval subject does not match intent diff subject")
    if approval.intent_diff_digest != expected_diff_digest:
        issues.append("approval intent_diff_digest does not match intent diff")
    known = {item.change_id for item in diff.changes}
    unknown = sorted(set(approval.approved_change_ids) - known)
    if unknown:
        issues.append(f"approval references unknown intent changes: {', '.join(unknown)}")
    if approval.approval_digest != compute_intent_approval_digest(approval):
        issues.append("approval_digest does not match approval evidence")
    return issues


def unapproved_intent_changes(
    diff: IntentDiff,
    approvals: list[IntentApprovalEvidence],
) -> list[str]:
    """Return change IDs without valid approval evidence for this exact diff."""

    approved: set[str] = set()
    for approval in approvals:
        if not verify_intent_approval(diff, approval):
            approved.update(approval.approved_change_ids)
    return sorted({item.change_id for item in diff.changes} - approved)
