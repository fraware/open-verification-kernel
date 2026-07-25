"""Core data models for Open Verification Kernel.

These models intentionally mirror the JSON schemas in ``schemas/``. They are lightweight
starter objects for the first implementation and should remain conservative about claims.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class VerificationStatus(str, Enum):
    """Checker claim status (not the merge decision lattice)."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    ERROR = "error"
    SKIPPED = "skipped"


class DecisionState(str, Enum):
    """Normative merge decision lattice (OVK-03).

    Checker claim statuses remain ``VerificationStatus``. Legacy
    ``MergeRecommendation`` values map onto this lattice via aliases;
    ``allow_with_warning`` is not a lattice member.
    """

    ALLOW = "allow"
    BLOCK = "block"
    NEEDS_REVIEW = "needs_review"
    UNKNOWN = "unknown"
    ERROR = "error"
    SKIPPED = "skipped"


class MergeRecommendation(str, Enum):
    """Deprecated alias vocabulary for ``DecisionState``.

    Prefer ``DecisionState``. Mapping:
    ``require_human_review`` ↔ ``needs_review``;
    ``allow_with_warning`` / ``require_stronger_check`` are legacy emission
    aliases only (not lattice members).
    """

    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_HUMAN_REVIEW = "require_human_review"
    ALLOW_WITH_WARNING = "allow_with_warning"
    REQUIRE_STRONGER_CHECK = "require_stronger_check"


class FindingContribution(BaseModel):
    """Per-finding contribution to an aggregated decision."""

    finding_id: str
    claim_status: VerificationStatus
    required: bool = True
    contribution: Literal["controlling", "supporting", "non_controlling", "warning"]
    detail: str | None = None


class RiskSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceRange(BaseModel):
    """Byte- or line-oriented span within a repository path."""

    path: str
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None


class VerificationSubject(BaseModel):
    """Repository revision under verification (matches evidence subject shape)."""

    repo: str
    head_sha: str
    pull_request: int | str | None = None
    base_sha: str | None = None


class VerificationIntent(BaseModel):
    intent_id: str
    version: str = "0.1.0"
    domain: str
    title: str
    description: str | None = None
    property: dict[str, Any]
    risk: dict[str, Any]
    merge_policy: dict[str, Any]
    scope: dict[str, Any] = Field(default_factory=dict)
    actor: dict[str, Any] = Field(default_factory=dict)
    resource: dict[str, Any] = Field(default_factory=dict)
    operation: str | None = None
    failure_modes: list[str] = Field(default_factory=list)
    acceptable_evidence: list[dict[str, Any]] = Field(default_factory=list)


class BackendClaim(BaseModel):
    backend: str
    guarantee_type: str
    status: VerificationStatus
    assumptions: list[str] = Field(default_factory=list)
    limits: list[str] = Field(default_factory=list)
    tool_version: str | None = None
    adapter_version: str | None = None
    # When present on evidence claims, drives required vs optional lattice rules.
    required: bool = True


class VerificationEvidence(BaseModel):
    evidence_id: str
    schema_version: str = "ovk.evidence.v1"
    subject: dict[str, Any]
    intent: dict[str, Any]
    backend_claims: list[BackendClaim]
    decision: dict[str, Any]
    change_origin: dict[str, Any] = Field(default_factory=dict)
    counterexamples: list[dict[str, Any]] = Field(default_factory=list)
    generated_artifacts: list[dict[str, Any]] = Field(default_factory=list)
    # Evidence v2 control-plane preview fields (optional for v1 read compatibility).
    obligation_id: str | None = None
    routing_id: str | None = None
    compiler: dict[str, Any] | None = None
    materials: list[dict[str, Any]] | None = None
    material_set_digest: str | None = None
    coverage: dict[str, Any] | None = None
    requested_backends: list[str] | None = None
    eligible_backends: list[str] | None = None
    selected_backends: list[str] | None = None
    attempted_backends: list[str] | None = None
    executed_backends: list[str] | None = None
    execution_attempts: list[dict[str, Any]] | None = None
    aggregation_policy: str | None = None
    routing_enforced: bool = False
    # Integrity envelope helper fields (OVK-04 / ovk.evidence.v3).
    ovk_version: str | None = None
    checker_id: str | None = None
    checker_version: str | None = None
    input_digest: str | None = None
    relevant_file_digests: list[dict[str, Any]] | None = None
    configuration_digest: str | None = None
    policy_digest: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    assumptions: list[str] | None = None
    unknowns: list[str] | None = None
    stderr: str | None = None
    exit_status: int | None = None
    evidence_digest: str | None = None
    signature: dict[str, Any] | None = None


class EvidenceBundle(BaseModel):
    bundle_id: str
    schema_version: str = "ovk.bundle.v1"
    subject: dict[str, Any]
    evidence: list[VerificationEvidence]
    decision: dict[str, Any]
    open_obligations: list[dict[str, Any]] = Field(default_factory=list)


Decision = Literal[
    "allow",
    "block",
    "needs_review",
    "unknown",
    "error",
    "skipped",
]

# Deprecated literal union retained for older call sites.
LegacyMergeDecision = Literal[
    "allow",
    "block",
    "require_human_review",
    "allow_with_warning",
    "require_stronger_check",
]
