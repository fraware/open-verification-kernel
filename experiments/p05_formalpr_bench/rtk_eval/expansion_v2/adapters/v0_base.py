"""Shared base for source-universe-v0 adapters (CertifyEdge, pcs-core)."""

from __future__ import annotations

import hashlib
import json
import tempfile
from abc import abstractmethod
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..adapter_contract import (
    ClaimAnchor,
    EvidenceSnapshot,
    GovernedArtifact,
    NativeValidatorResult,
    RepositoryIdentity,
    SourceEvidenceCandidate,
    SourceRepositoryAdapter,
    SubjectBinding,
    TransitionEnumerationRecord,
)
from . import common_git, v0_bridge


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class V0SourceAdapter(SourceRepositoryAdapter):
    """Adapter that reuses authentic v0 extract/materialize semantics."""

    def __init__(self, identity: RepositoryIdentity) -> None:
        self._identity = identity

    @property
    def identity(self) -> RepositoryIdentity:
        return self._identity

    @property
    def implementation_status(self) -> str:
        return "READY_FOR_MATERIALIZATION"

    def enumerate_transitions(
        self,
        checkout: Path,
        *,
        cutoff_sha: str | None = None,
    ) -> Sequence[TransitionEnumerationRecord]:
        cutoff = cutoff_sha or self.identity.cutoff_sha
        return common_git.enumerate_first_parent_transitions(
            checkout,
            repository=self.repository,
            cutoff_sha=cutoff,
        )

    @abstractmethod
    def discover_governed_artifacts(
        self,
        checkout: Path,
        revision: str,
    ) -> Sequence[GovernedArtifact]:
        raise NotImplementedError

    def extract_claim_anchors(
        self,
        checkout: Path,
        transition: TransitionEnumerationRecord,
    ) -> Sequence[ClaimAnchor]:
        if transition.eligibility != "ELIGIBLE":
            return []
        raw = v0_bridge.extract_anchors_for_transition(
            self.repository,
            checkout,
            transition.as_dict(),
        )
        out: list[ClaimAnchor] = []
        for row in raw:
            out.append(
                ClaimAnchor(
                    anchor_id=str(row["anchor_id"]),
                    repository=str(row["repository"]),
                    family=str(row["family"]),
                    claim_id=str(row["claim_id"]),
                    contract_locator=str(row["contract_locator"]),
                    source_sha=str(row["source_sha"]),
                    target_sha=str(row["target_sha"]),
                    payload=row,
                )
            )
        return out

    def discover_source_evidence_candidates(
        self,
        checkout: Path,
        anchor: ClaimAnchor,
    ) -> Sequence[SourceEvidenceCandidate]:
        # Candidates are discovered during source-revision native validation in
        # the authentic materializer. Expose the contract locator as a seed.
        return [
            SourceEvidenceCandidate(
                candidate_id=f"seed:{anchor.anchor_id}",
                anchor_id=anchor.anchor_id,
                paths=(anchor.contract_locator,),
                discovery_rule="authentic_v0_materializer_seed",
            )
        ]

    def execute_source_revision_native_validator(
        self,
        checkout: Path,
        candidate: SourceEvidenceCandidate,
        *,
        source_sha: str,
    ) -> NativeValidatorResult:
        # Full materialization is performed by materialize_anchor_record using
        # authentic modules; this method exposes a source-side-only status hook.
        return NativeValidatorResult(
            status="DELEGATED_TO_AUTHENTIC_MATERIALIZER",
            validator_id="authentic_v0_materializer",
            accepted=False,
            details={
                "candidate_id": candidate.candidate_id,
                "source_sha": source_sha,
                "note": (
                    "Use materialize_anchor_record for complete SOURCE_* status "
                    "under frozen evidence-snapshot policy."
                ),
            },
        )

    def materialize_anchor_record(
        self,
        checkout: Path,
        anchor: ClaimAnchor,
        *,
        timeout_sec: int = 1800,
        work_root: Path | None = None,
        cache: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run authentic family materializer at the anchor source revision."""
        payload = dict(anchor.payload)
        if not payload:
            raise ValueError("ClaimAnchor.payload must carry authentic anchor row")
        mse = v0_bridge.materialize_source_evidence
        temp_owner = None
        if work_root is None:
            temp_owner = tempfile.TemporaryDirectory(prefix="rtk-v0-adapter-")
            root = Path(temp_owner.name)
        else:
            root = work_root
        try:
            group_root = root / mse._typed_digest(
                "rtk-source-worktree-v0",
                {"repository": self.repository, "source_sha": anchor.source_sha},
            )
            group_root.mkdir(parents=True, exist_ok=True)
            with mse._source_worktree(
                checkout, anchor.source_sha, group_root
            ) as worktree:
                return v0_bridge.materialize_anchor(
                    payload,
                    worktree,
                    timeout_sec=timeout_sec,
                    cache=cache if cache is not None else {},
                )
        finally:
            if temp_owner is not None:
                temp_owner.cleanup()

    def bind_subject(
        self,
        anchor: ClaimAnchor,
        validator_result: NativeValidatorResult,
    ) -> SubjectBinding:
        details = dict(validator_result.details)
        subject = details.get("subject_binding")
        if not isinstance(subject, str) or not subject:
            subject = f"PENDING:{anchor.anchor_id}"
        digest = _sha256(
            _canonical_bytes(
                {
                    "anchor_id": anchor.anchor_id,
                    "subject": subject,
                    "validator_id": validator_result.validator_id,
                    "status": validator_result.status,
                }
            )
        )
        return SubjectBinding(
            subject_id=str(subject),
            anchor_id=anchor.anchor_id,
            binding_digest=digest,
            payload=details,
        )

    def construct_evidence_snapshot(
        self,
        checkout: Path,
        binding: SubjectBinding,
        *,
        source_sha: str,
        artifacts: Sequence[GovernedArtifact],
    ) -> EvidenceSnapshot:
        art_rows = tuple(
            {"path": a.path, "sha256": a.sha256 or ""}
            for a in artifacts
        )
        digest = _sha256(
            _canonical_bytes(
                {
                    "repository": self.repository,
                    "revision": source_sha,
                    "binding_digest": binding.binding_digest,
                    "artifacts": list(art_rows),
                }
            )
        )
        return EvidenceSnapshot(
            snapshot_id=f"snap:{digest[:32]}",
            repository=self.repository,
            revision=source_sha,
            digest=digest,
            artifacts=art_rows,
            completeness_policy={
                "policy_id": "expansion_v2_v0_adapter_snapshot",
                "source_bytes_only": True,
            },
        )

    def claim_anchor_from_payload(self, row: Mapping[str, Any]) -> ClaimAnchor:
        return ClaimAnchor(
            anchor_id=str(row["anchor_id"]),
            repository=str(row["repository"]),
            family=str(row["family"]),
            claim_id=str(row["claim_id"]),
            contract_locator=str(row["contract_locator"]),
            source_sha=str(row["source_sha"]),
            target_sha=str(row["target_sha"]),
            payload=dict(row),
        )
