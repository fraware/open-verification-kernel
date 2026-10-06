"""Generic source-repository adapter contract for expansion_v2.

Repository-specific semantic mapping must not be used for expansion-candidate
materialization until this interface and its tests are frozen and the v0
compatibility harness has passed (or is explicitly blocked on adapter
implementation with reason ADAPTER_NOT_YET_IMPLEMENTED).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from .prohibitions import PROHIBITED_CAPABILITIES, refuse_prohibited
from .reason_codes import ExclusionReasonCode


ADAPTER_METHOD_NAMES: tuple[str, ...] = (
    "enumerate_transitions",
    "discover_governed_artifacts",
    "extract_claim_anchors",
    "discover_source_evidence_candidates",
    "execute_source_revision_native_validator",
    "bind_subject",
    "construct_evidence_snapshot",
)


@dataclass(frozen=True)
class RepositoryIdentity:
    """Frozen identity for a source repository under evaluation."""

    repository: str
    url: str
    cutoff_sha: str
    history_rule: str = "FIRST_PARENT"
    role: str = "EXPANSION_CANDIDATE"


@dataclass(frozen=True)
class TransitionEnumerationRecord:
    """One FIRST_PARENT transition, admitted or excluded with reason."""

    transition_id: str
    repository: str
    source_sha: str
    target_sha: str
    source_timestamp: str | None
    target_timestamp: str | None
    changed_paths: tuple[str, ...]
    eligibility: str  # ELIGIBLE | EXCLUDED
    exclusion_reason: str | None = None
    history_rule: str = "FIRST_PARENT"
    candidate_semantic_categories: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "repository": self.repository,
            "source_sha": self.source_sha,
            "target_sha": self.target_sha,
            "source_timestamp": self.source_timestamp,
            "target_timestamp": self.target_timestamp,
            "changed_paths": list(self.changed_paths),
            "candidate_semantic_categories": list(self.candidate_semantic_categories),
            "eligibility": self.eligibility,
            "exclusion_reason": self.exclusion_reason,
            "history_rule": self.history_rule,
        }


@dataclass(frozen=True)
class GovernedArtifact:
    path: str
    artifact_class: str
    sha256: str | None = None


@dataclass(frozen=True)
class ClaimAnchor:
    anchor_id: str
    repository: str
    family: str
    claim_id: str
    contract_locator: str
    source_sha: str
    target_sha: str
    payload: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SourceEvidenceCandidate:
    candidate_id: str
    anchor_id: str
    paths: tuple[str, ...]
    discovery_rule: str


@dataclass(frozen=True)
class NativeValidatorResult:
    status: str
    validator_id: str
    accepted: bool
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SubjectBinding:
    subject_id: str
    anchor_id: str
    binding_digest: str
    payload: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvidenceSnapshot:
    snapshot_id: str
    repository: str
    revision: str
    digest: str
    digest_algorithm: str = "sha256"
    completeness_policy: Mapping[str, Any] = field(default_factory=dict)
    artifacts: tuple[Mapping[str, str], ...] = ()


class SourceRepositoryAdapter(ABC):
    """Repository-independent source-side adapter surface.

    Implementations supply repository-specific *discovery* rules but must obey
    the shared prohibitions and never consult RTK, oracle labels, target
    validators, or unblinded information.
    """

    @property
    @abstractmethod
    def identity(self) -> RepositoryIdentity:
        raise NotImplementedError

    @property
    def repository(self) -> str:
        return self.identity.repository

    @property
    def implementation_status(self) -> str:
        """INTERFACE_STUB | SEMANTIC_MAPPING_PENDING | READY_FOR_MATERIALIZATION."""
        return "INTERFACE_STUB"

    def assert_source_side_only(self) -> None:
        """Confirm this adapter is bound to the source-side prohibition set.

        Default implementation is a documentation hook: calling a prohibited
        capability must go through ``refuse_prohibited`` (which raises).
        Subclasses may override with stronger static or runtime checks.
        """
        _ = PROHIBITED_CAPABILITIES
        _ = refuse_prohibited  # imported for contract visibility / tests

    @abstractmethod
    def enumerate_transitions(
        self,
        checkout: Path,
        *,
        cutoff_sha: str | None = None,
    ) -> Sequence[TransitionEnumerationRecord]:
        """Deterministic FIRST_PARENT transition enumeration up to cutoff."""

    @abstractmethod
    def discover_governed_artifacts(
        self,
        checkout: Path,
        revision: str,
    ) -> Sequence[GovernedArtifact]:
        """Discover governed artifacts at a source revision."""

    @abstractmethod
    def extract_claim_anchors(
        self,
        checkout: Path,
        transition: TransitionEnumerationRecord,
    ) -> Sequence[ClaimAnchor]:
        """Extract historical claim anchors for one transition."""

    @abstractmethod
    def discover_source_evidence_candidates(
        self,
        checkout: Path,
        anchor: ClaimAnchor,
    ) -> Sequence[SourceEvidenceCandidate]:
        """Discover source-evidence candidates for an anchor."""

    @abstractmethod
    def execute_source_revision_native_validator(
        self,
        checkout: Path,
        candidate: SourceEvidenceCandidate,
        *,
        source_sha: str,
    ) -> NativeValidatorResult:
        """Run validators at the *source* revision only."""

    @abstractmethod
    def bind_subject(
        self,
        anchor: ClaimAnchor,
        validator_result: NativeValidatorResult,
    ) -> SubjectBinding:
        """Bind claim subject identity from source-side material only."""

    @abstractmethod
    def construct_evidence_snapshot(
        self,
        checkout: Path,
        binding: SubjectBinding,
        *,
        source_sha: str,
        artifacts: Sequence[GovernedArtifact],
    ) -> EvidenceSnapshot:
        """Construct a content-addressed evidence snapshot."""


class AdapterNotYetImplemented(SourceRepositoryAdapter):
    """Placeholder adapter that preserves contract shape without semantics.

    Used for expansion candidates (and optionally v0 repos) until
    repository-specific mapping is reviewed and implemented. All semantic
    methods raise with reason ADAPTER_NOT_YET_IMPLEMENTED.
    """

    def __init__(self, identity: RepositoryIdentity) -> None:
        self._identity = identity

    @property
    def identity(self) -> RepositoryIdentity:
        return self._identity

    @property
    def implementation_status(self) -> str:
        return "SEMANTIC_MAPPING_PENDING"

    def _nyi(self, method: str) -> None:
        raise NotImplementedError(
            f"{self.repository}.{method}: "
            f"{ExclusionReasonCode.ADAPTER_NOT_YET_IMPLEMENTED.value}"
        )

    def enumerate_transitions(
        self,
        checkout: Path,
        *,
        cutoff_sha: str | None = None,
    ) -> Sequence[TransitionEnumerationRecord]:
        self._nyi("enumerate_transitions")
        raise AssertionError("unreachable")

    def discover_governed_artifacts(
        self,
        checkout: Path,
        revision: str,
    ) -> Sequence[GovernedArtifact]:
        self._nyi("discover_governed_artifacts")
        raise AssertionError("unreachable")

    def extract_claim_anchors(
        self,
        checkout: Path,
        transition: TransitionEnumerationRecord,
    ) -> Sequence[ClaimAnchor]:
        self._nyi("extract_claim_anchors")
        raise AssertionError("unreachable")

    def discover_source_evidence_candidates(
        self,
        checkout: Path,
        anchor: ClaimAnchor,
    ) -> Sequence[SourceEvidenceCandidate]:
        self._nyi("discover_source_evidence_candidates")
        raise AssertionError("unreachable")

    def execute_source_revision_native_validator(
        self,
        checkout: Path,
        candidate: SourceEvidenceCandidate,
        *,
        source_sha: str,
    ) -> NativeValidatorResult:
        self._nyi("execute_source_revision_native_validator")
        raise AssertionError("unreachable")

    def bind_subject(
        self,
        anchor: ClaimAnchor,
        validator_result: NativeValidatorResult,
    ) -> SubjectBinding:
        self._nyi("bind_subject")
        raise AssertionError("unreachable")

    def construct_evidence_snapshot(
        self,
        checkout: Path,
        binding: SubjectBinding,
        *,
        source_sha: str,
        artifacts: Sequence[GovernedArtifact],
    ) -> EvidenceSnapshot:
        self._nyi("construct_evidence_snapshot")
        raise AssertionError("unreachable")
