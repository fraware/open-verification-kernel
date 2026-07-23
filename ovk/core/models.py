"""Core data models for Open Verification Kernel.

These models intentionally mirror the JSON schemas in ``schemas/``. They are lightweight
starter objects for the first implementation and should remain conservative about claims.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class VerificationStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    ERROR = "error"
    SKIPPED = "skipped"


class MergeRecommendation(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_HUMAN_REVIEW = "require_human_review"
    ALLOW_WITH_WARNING = "allow_with_warning"
    REQUIRE_STRONGER_CHECK = "require_stronger_check"


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
    coverage: dict[str, Any] | None = None
    requested_backends: list[str] | None = None
    eligible_backends: list[str] | None = None
    selected_backends: list[str] | None = None
    attempted_backends: list[str] | None = None
    executed_backends: list[str] | None = None
    execution_attempts: list[dict[str, Any]] | None = None
    aggregation_policy: str | None = None
    routing_enforced: bool = False


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
    "require_human_review",
    "allow_with_warning",
    "require_stronger_check",
]
