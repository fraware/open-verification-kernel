"""External candidate coverage accounting for durable assurance qualification.

The registry exists to prevent selection bias. Public security candidates are
recorded before deciding whether the current Protected Effect semantics can
express them. Unsupported or incompletely evidenced candidates remain visible in
the denominator.

This module reports representational coverage only. It does not promote a
candidate into independent-external qualification evidence. That requires an
actual pinned replay result and, for the production human-depth gate, explicit
qualification adjudication.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ovk.core.schema_validation import load_json, require_schema_valid
from ovk.paths import schema_path


CandidateTriageStatus = Literal[
    "supported_now",
    "unsupported_semantics",
    "requires_new_guarantee_family",
    "insufficient_public_evidence",
]


class ExternalAssuranceCandidate(BaseModel):
    candidate_id: str
    repository: str
    framework: str
    security_property: str
    triage_status: CandidateTriageStatus
    semantic_pattern: str
    reason_codes: list[str]
    references: list[str]
    qualification_eligible: bool = False
    repository_url: str | None = None
    base_sha: str | None = None
    head_sha: str | None = None
    fix_pr: str | None = None
    notes: str = ""

    @field_validator(
        "candidate_id",
        "repository",
        "framework",
        "security_property",
        "semantic_pattern",
    )
    @classmethod
    def _non_empty_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("external candidate identity fields must be non-empty")
        return value

    @field_validator("reason_codes", "references")
    @classmethod
    def _non_empty_lists(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values if value.strip()]
        if not normalized:
            raise ValueError("candidate reason/reference collections must be non-empty")
        if len(normalized) != len(set(normalized)):
            raise ValueError("candidate reason/reference collections must be unique")
        return normalized

    @model_validator(mode="after")
    def _qualification_boundary(self) -> "ExternalAssuranceCandidate":
        if self.triage_status != "supported_now" and self.qualification_eligible:
            raise ValueError(
                "only supported_now candidates may be marked qualification_eligible"
            )
        if self.triage_status == "supported_now":
            if self.base_sha is None or self.head_sha is None:
                raise ValueError(
                    "supported_now candidates require pinned base/head revisions"
                )
        return self


class ExternalCandidateRegistry(BaseModel):
    schema_version: Literal[
        "ovk.assurance_external_candidate_registry.v1"
    ] = "ovk.assurance_external_candidate_registry.v1"
    registry_id: str
    description: str = ""
    reviewed_against: dict[str, str | None]
    candidates: list[ExternalAssuranceCandidate]

    @model_validator(mode="after")
    def _unique_candidates(self) -> "ExternalCandidateRegistry":
        ids = [item.candidate_id for item in self.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("external candidate IDs must be unique")
        return self


class ExternalCandidateCoverageSummary(BaseModel):
    registry_id: str
    candidates_total: int = Field(ge=0)
    evaluable_semantic_candidates: int = Field(ge=0)
    supported_now: int = Field(ge=0)
    unsupported_semantics: int = Field(ge=0)
    requires_new_guarantee_family: int = Field(ge=0)
    insufficient_public_evidence: int = Field(ge=0)
    qualification_eligible_candidates: int = Field(ge=0)
    representational_coverage_rate: float | None = Field(
        default=None,
        ge=0,
        le=1,
    )
    qualification_ready_rate: float | None = Field(
        default=None,
        ge=0,
        le=1,
    )


def load_external_candidate_registry(path: Path) -> ExternalCandidateRegistry:
    payload = json.loads(path.read_text(encoding="utf-8"))
    require_schema_valid(
        payload,
        load_json(
            schema_path("assurance.external_candidate_registry.schema.json")
        ),
        context="external assurance candidate registry",
    )
    return ExternalCandidateRegistry.model_validate(payload)


def summarize_external_candidate_coverage(
    registry: ExternalCandidateRegistry,
) -> ExternalCandidateCoverageSummary:
    counts = {
        status: sum(
            1 for item in registry.candidates if item.triage_status == status
        )
        for status in (
            "supported_now",
            "unsupported_semantics",
            "requires_new_guarantee_family",
            "insufficient_public_evidence",
        )
    }

    # Evidence insufficiency is excluded from the semantic-coverage denominator:
    # it does not yet tell us whether the current model can express a repaired
    # transition. Every other triaged status represents an actual semantic
    # classification and remains in the denominator.
    evaluable = (
        counts["supported_now"]
        + counts["unsupported_semantics"]
        + counts["requires_new_guarantee_family"]
    )
    qualification_eligible = sum(
        1 for item in registry.candidates if item.qualification_eligible
    )

    representational = (
        counts["supported_now"] / evaluable
        if evaluable
        else None
    )
    qualification_ready = (
        qualification_eligible / len(registry.candidates)
        if registry.candidates
        else None
    )

    return ExternalCandidateCoverageSummary(
        registry_id=registry.registry_id,
        candidates_total=len(registry.candidates),
        evaluable_semantic_candidates=evaluable,
        supported_now=counts["supported_now"],
        unsupported_semantics=counts["unsupported_semantics"],
        requires_new_guarantee_family=counts[
            "requires_new_guarantee_family"
        ],
        insufficient_public_evidence=counts[
            "insufficient_public_evidence"
        ],
        qualification_eligible_candidates=qualification_eligible,
        representational_coverage_rate=representational,
        qualification_ready_rate=qualification_ready,
    )
