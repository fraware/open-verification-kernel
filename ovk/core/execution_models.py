"""Typed execution-plane models for the solver-agnostic control plane.

These models are the serialization and digest foundation for obligations, routing,
backend execution, and coverage. They intentionally do not change runtime behavior;
later PRs wire them into the registry, router, and control plane.

Invariants
----------
* ``obligation_id`` is a content digest of all semantically relevant obligation
  fields except ``obligation_id`` itself.
* ``routing_id`` digests routing components including router version and budget.
* Material ``uri`` values are repository-relative or use a documented scheme;
  arbitrary absolute local paths are rejected.
* Digests use the same canonical JSON hashing as ``ovk.core.bundle.content_digest``.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from ovk.core.bundle import content_digest
from ovk.core.models import (
    MergeRecommendation,
    RiskSeverity,
    SourceRange,
    VerificationStatus,
    VerificationSubject,
)

# Documented material URI schemes. Bare repository-relative paths are also allowed.
ALLOWED_MATERIAL_URI_SCHEMES: frozenset[str] = frozenset(
    {
        "repo",
        "ovk-material",
        "https",
        "http",
        "git",
    }
)

MaterialKind = Literal[
    "diff",
    "source_file",
    "workflow",
    "terraform_plan",
    "kubernetes_object",
    "policy",
    "branch_protection",
    "deployment_policy",
    "generated_harness",
    "explicit_harness",
]

CoverageStatus = Literal["complete", "partial", "unknown", "inapplicable"]
SupportLevel = Literal["supported", "partial", "unsupported", "unavailable"]
TerminationKind = Literal[
    "completed",
    "timeout",
    "resource_exhausted",
    "tool_unavailable",
    "tool_error",
    "invalid_output",
    "cancelled",
]
FallbackOutcome = Literal["unknown", "error", "fail", "fallback"]
TimeoutBehavior = Literal["unknown", "error", "fail"]

_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_URI_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")


def is_absolute_local_path(uri: str) -> bool:
    """Return True when *uri* looks like an absolute local filesystem path."""
    value = uri.strip()
    if not value:
        return False
    if value.startswith("\\\\") or value.startswith("//"):
        # UNC paths (\\server\share) or protocol-relative //host — treat as absolute local/network paths.
        if value.startswith("//") and not value.lower().startswith(("//repo",)):
            # protocol-relative URLs are not repo-relative materials
            return True
        return value.startswith("\\\\")
    if _WINDOWS_DRIVE_RE.match(value):
        return True
    if value.startswith("file:"):
        return True
    # POSIX absolute path without a documented scheme
    if value.startswith("/") and not _URI_SCHEME_RE.match(value):
        return True
    return False


def validate_material_uri(uri: str) -> str:
    """Validate a material URI; reject empty values and absolute local paths.

    Allowed forms:
    * repository-relative paths (``src/foo.py``, ``.github/workflows/ci.yml``)
    * documented schemes in ``ALLOWED_MATERIAL_URI_SCHEMES`` (``repo:...``, ``ovk-material:...``, ...)
    """
    value = uri.strip()
    if not value:
        raise ValueError("material uri must be non-empty")
    if is_absolute_local_path(value):
        raise ValueError(
            "material uri must not be an arbitrary absolute local path; "
            "use a repository-relative path or a documented material scheme"
        )
    scheme_match = _URI_SCHEME_RE.match(value)
    if scheme_match is not None:
        scheme = scheme_match.group(1).lower()
        # Windows drive letters are already rejected above; remaining schemes must be allowlisted.
        if len(scheme) == 1 and scheme.isalpha():
            raise ValueError("material uri must not use a filesystem drive letter")
        if scheme not in ALLOWED_MATERIAL_URI_SCHEMES:
            raise ValueError(
                f"material uri scheme {scheme!r} is not allowed; "
                f"permitted schemes: {sorted(ALLOWED_MATERIAL_URI_SCHEMES)}"
            )
    return value


def _dump_json(value: BaseModel | dict[str, Any] | list[Any] | Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return value


def _sorted_str_list(values: list[str]) -> list[str]:
    return sorted(values)


def _sorted_by_key(items: list[Any], key: str) -> list[Any]:
    dumped = [_dump_json(item) for item in items]
    return sorted(dumped, key=lambda item: str(item.get(key, "")))


# ---------------------------------------------------------------------------
# Supporting identity / capability / environment types
# ---------------------------------------------------------------------------


class CompilerIdentity(BaseModel):
    """Compiler that produced an obligation or abstraction."""

    compiler_id: str
    compiler_version: str


class BackendToolIdentity(BaseModel):
    """Tool and adapter identity inside a capability manifest."""

    name: str
    adapter: str
    adapter_version: str
    version: str | None = None


class BackendGuaranteeDeclaration(BaseModel):
    """Guarantee semantics advertised by a backend."""

    type: str
    meaning_of_pass: str
    meaning_of_fail: str
    meaning_of_unknown: str


class BackendCapabilityManifest(BaseModel):
    """Typed capability declaration for a registered backend."""

    capability_id: str
    tool: BackendToolIdentity
    backend_class: str
    guarantee: BackendGuaranteeDeclaration
    input_languages: list[str] = Field(default_factory=list)
    supported_domains: list[str] = Field(default_factory=list)
    supported_property_kinds: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    limits: list[str] = Field(default_factory=list)
    result_format: str | None = None
    counterexample_format: str | None = None
    timeout_behavior: TimeoutBehavior = "unknown"


class BackendEnvironmentFingerprint(BaseModel):
    """Environment fingerprint recorded before or after backend execution."""

    backend: str
    adapter_version: str
    environment_digest: str
    tool_version: str | None = None
    tool_digest: str | None = None
    worker_image_digest: str | None = None
    native_available: bool = False


class ExecutionBudget(BaseModel):
    """Runtime and isolation budget for obligation execution."""

    total_wall_time_seconds: float
    per_backend_wall_time_seconds: float
    max_memory_mb: int
    max_parallel_backends: int
    allow_network: bool
    allow_repository_write: bool
    allowed_backends: list[str] | None = None
    denied_backends: list[str] = Field(default_factory=list)


class FallbackPolicy(BaseModel):
    """Policy controlling whether and how backends may fall back."""

    allow_fallback: bool = False
    fallback_backends: list[str] = Field(default_factory=list)
    acceptable_fallback_guarantees: list[str] = Field(default_factory=list)
    on_timeout: FallbackOutcome = "unknown"
    on_tool_unavailable: FallbackOutcome = "unknown"
    on_invalid_output: FallbackOutcome = "unknown"
    on_resource_exhausted: FallbackOutcome = "unknown"

    def outcome_for_termination(self, termination: TerminationKind | str) -> FallbackOutcome:
        """Map a termination kind to the configured fallback outcome."""
        mapping: dict[str, FallbackOutcome] = {
            "timeout": self.on_timeout,
            "tool_unavailable": self.on_tool_unavailable,
            "invalid_output": self.on_invalid_output,
            "resource_exhausted": self.on_resource_exhausted,
        }
        return mapping.get(str(termination), "unknown")


class BackendCapabilityAssessment(BaseModel):
    """Assessment of whether a backend can handle an obligation."""

    backend: str
    support: SupportLevel
    score: float
    guarantee_type: str
    material_requirements_met: bool
    coverage_requirements_met: bool
    native_available: bool
    estimated_wall_time_seconds: float
    estimated_memory_mb: int
    reasons: list[str] = Field(default_factory=list)


class BackendCandidate(BaseModel):
    """Eligible backend considered during routing."""

    backend: str
    score: float
    support: SupportLevel
    guarantee_type: str
    reasons: list[str] = Field(default_factory=list)
    native_available: bool = False


class BackendSelection(BaseModel):
    """Backend selected for execution."""

    backend: str
    reason: str
    expected_guarantee: str
    required: bool = True
    score: float = 0.0


class BackendRejection(BaseModel):
    """Backend considered and rejected during routing."""

    backend: str
    reason: str
    support: SupportLevel | None = None


class HumanExplanation(BaseModel):
    """Human-readable explanation of a normalized backend result."""

    summary: str
    repair_hint: str
    failure_mode: str | None = None


class ExecutionContext(BaseModel):
    """Repository and policy context supplied to adapters and the registry."""

    subject: VerificationSubject
    actor_type: str = "unknown"
    changed_files: list[str] = Field(default_factory=list)
    policy_digest: str | None = None
    budget: ExecutionBudget | None = None
    surfaces: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Core execution-plane models
# ---------------------------------------------------------------------------


class MaterialReference(BaseModel):
    """Content-addressed reference to an input material."""

    material_id: str
    kind: MaterialKind
    uri: str
    sha256: str
    size_bytes: int
    source_revision: str | None = None
    source_range: SourceRange | None = None
    trusted: bool = False

    @field_validator("uri")
    @classmethod
    def _check_uri(cls, value: str) -> str:
        return validate_material_uri(value)


class AbstractionCoverage(BaseModel):
    """How completely a compiler abstracted the subject materials."""

    status: CoverageStatus
    confidence: float
    extracted_elements: int
    expected_elements: int | None = None
    unsupported_constructs: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    source_ranges: list[SourceRange] = Field(default_factory=list)


class VerificationObligation(BaseModel):
    """Backend-neutral verification obligation (schema ``ovk.obligation.v1``)."""

    obligation_id: str
    schema_version: Literal["ovk.obligation.v1"] = "ovk.obligation.v1"
    subject: VerificationSubject
    intent_id: str
    intent_version: str
    lane: str
    property_kind: str
    severity: RiskSeverity
    compiler_id: str
    compiler_version: str
    materials: list[MaterialReference]
    abstraction: dict[str, Any]
    abstraction_digest: str
    coverage: AbstractionCoverage
    acceptable_guarantees: list[str]
    required_capabilities: list[str]
    policy_digest: str


class RoutingDecision(BaseModel):
    """Typed routing decision for one obligation (schema ``ovk.routing.v1``)."""

    routing_id: str
    schema_version: Literal["ovk.routing.v1"] = "ovk.routing.v1"
    obligation_id: str
    requested: list[str]
    eligible: list[BackendCandidate]
    selected: list[BackendSelection]
    rejected: list[BackendRejection]
    aggregation_policy: str
    fallback_policy: FallbackPolicy
    budget: ExecutionBudget
    policy_digest: str


class BackendObligation(BaseModel):
    """Backend-specific compiled obligation ready for execution."""

    backend_obligation_id: str
    obligation_id: str
    routing_id: str
    backend: str
    adapter_version: str
    compiler_version: str
    input_language: str
    payload: dict[str, Any]
    payload_digest: str
    command_plan: list[str] = Field(default_factory=list)
    environment_requirements: dict[str, Any] = Field(default_factory=dict)
    expected_guarantee: str


class RawBackendExecution(BaseModel):
    """Raw backend execution artifact before normalization."""

    backend: str
    backend_obligation_id: str
    termination: TerminationKind
    native_execution: bool
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    raw_result: dict[str, Any] = Field(default_factory=dict)
    stdout_digest: str | None = None
    stderr_digest: str | None = None
    raw_result_digest: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    duration_ms: float | None = None
    tool_version: str | None = None
    tool_digest: str | None = None
    worker_image_digest: str | None = None


class ExecutionAttempt(BaseModel):
    """One recorded attempt to execute a backend obligation."""

    attempt_id: str
    backend_obligation_id: str
    backend: str
    required: bool
    started_at: str
    finished_at: str
    duration_ms: float
    termination: TerminationKind
    native_execution: bool
    tool_version: str | None = None
    tool_digest: str | None = None
    worker_image_digest: str | None = None
    exit_code: int | None = None
    stdout_digest: str | None = None
    stderr_digest: str | None = None
    raw_result_digest: str | None = None


class NormalizedBackendResult(BaseModel):
    """Normalized result produced from a raw backend execution."""

    attempt_id: str
    backend: str
    status: VerificationStatus
    guarantee_type: str
    assumptions: list[str] = Field(default_factory=list)
    limits: list[str] = Field(default_factory=list)
    counterexamples: list[dict[str, Any]] = Field(default_factory=list)
    generated_artifacts: list[dict[str, Any]] = Field(default_factory=list)


class CachedBackendExecution(BaseModel):
    """Provenance-preserving cache payload for a backend execution (ovk.cache.v3).

    Cache hits must replay this record rather than synthesizing a new attempt or
    re-inferring ``native_execution`` from current tool availability.
    """

    schema_version: Literal["ovk.cache.v3"] = "ovk.cache.v3"
    attempt: ExecutionAttempt
    native_execution: bool
    tool_version: str | None = None
    tool_digest: str | None = None
    termination: TerminationKind
    exit_code: int | None = None
    raw_result_digest: str | None = None
    environment_fingerprint: str
    normalized_result: NormalizedBackendResult


class ObligationExecutionRecord(BaseModel):
    """Full typed record of compiling, routing, and executing one obligation."""

    obligation: VerificationObligation
    routing: RoutingDecision
    backend_obligations: list[BackendObligation]
    attempts: list[ExecutionAttempt]
    results: list[NormalizedBackendResult]
    aggregate_status: VerificationStatus
    merge_recommendation: MergeRecommendation
    aggregation_reason: str
    open_obligations: list[dict[str, Any]] = Field(default_factory=list)
    fallback_used: bool = False
    fallback_accepted: bool = False
    fallback_cause: str | None = None


# ---------------------------------------------------------------------------
# Canonical digests
# ---------------------------------------------------------------------------


def compute_abstraction_digest(abstraction: dict[str, Any]) -> str:
    """Return the content digest of a property abstraction."""
    return content_digest(abstraction)


def compute_payload_digest(payload: dict[str, Any]) -> str:
    """Return the content digest of a backend obligation payload."""
    return content_digest(payload)


def obligation_digest_input(
    obligation: VerificationObligation | dict[str, Any],
) -> dict[str, Any]:
    """Return the canonical digest payload for an obligation (excludes ``obligation_id``)."""
    data = dict(_dump_json(obligation))
    data.pop("obligation_id", None)
    data["acceptable_guarantees"] = _sorted_str_list(list(data.get("acceptable_guarantees") or []))
    data["required_capabilities"] = _sorted_str_list(list(data.get("required_capabilities") or []))
    materials = list(data.get("materials") or [])
    data["materials"] = sorted(materials, key=lambda item: str(item.get("material_id", "")))
    return data


def compute_obligation_id(obligation: VerificationObligation | dict[str, Any]) -> str:
    """Compute ``obligation_id`` from all semantically relevant fields except itself."""
    return content_digest(obligation_digest_input(obligation))


def routing_digest_input(
    *,
    obligation_id: str,
    requested: list[str],
    eligible: list[BackendCandidate] | list[dict[str, Any]],
    selected: list[BackendSelection] | list[dict[str, Any]],
    rejected: list[BackendRejection] | list[dict[str, Any]],
    aggregation_policy: str,
    fallback_policy: FallbackPolicy | dict[str, Any],
    budget: ExecutionBudget | dict[str, Any],
    policy_digest: str,
    router_version: str,
    assessments: list[BackendCapabilityAssessment] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return the canonical digest payload used to derive ``routing_id``."""
    payload: dict[str, Any] = {
        "obligation_id": obligation_id,
        "requested": _sorted_str_list(list(requested)),
        "eligible": _sorted_by_key(list(eligible), "backend"),
        "selected": _sorted_by_key(list(selected), "backend"),
        "rejected": _sorted_by_key(list(rejected), "backend"),
        "aggregation_policy": aggregation_policy,
        "fallback_policy": _dump_json(fallback_policy),
        "budget": _dump_json(budget),
        "policy_digest": policy_digest,
        "router_version": router_version,
    }
    if assessments is not None:
        payload["assessments"] = _sorted_by_key(list(assessments), "backend")
    return payload


def compute_routing_id(
    *,
    obligation_id: str,
    requested: list[str],
    eligible: list[BackendCandidate] | list[dict[str, Any]],
    selected: list[BackendSelection] | list[dict[str, Any]],
    rejected: list[BackendRejection] | list[dict[str, Any]],
    aggregation_policy: str,
    fallback_policy: FallbackPolicy | dict[str, Any],
    budget: ExecutionBudget | dict[str, Any],
    policy_digest: str,
    router_version: str,
    assessments: list[BackendCapabilityAssessment] | list[dict[str, Any]] | None = None,
) -> str:
    """Compute ``routing_id`` from routing components and router version."""
    return content_digest(
        routing_digest_input(
            obligation_id=obligation_id,
            requested=requested,
            eligible=eligible,
            selected=selected,
            rejected=rejected,
            aggregation_policy=aggregation_policy,
            fallback_policy=fallback_policy,
            budget=budget,
            policy_digest=policy_digest,
            router_version=router_version,
            assessments=assessments,
        )
    )


def backend_obligation_digest_input(
    backend_obligation: BackendObligation | dict[str, Any],
) -> dict[str, Any]:
    """Canonical digest payload for a backend obligation (excludes its id)."""
    data = dict(_dump_json(backend_obligation))
    data.pop("backend_obligation_id", None)
    return data


def compute_backend_obligation_id(
    backend_obligation: BackendObligation | dict[str, Any],
) -> str:
    """Compute ``backend_obligation_id`` from semantically relevant fields except itself."""
    return content_digest(backend_obligation_digest_input(backend_obligation))


def attempt_digest_input(attempt: ExecutionAttempt | dict[str, Any]) -> dict[str, Any]:
    """Canonical digest payload for an execution attempt (excludes identity and timing).

    ``attempt_id``, wall-clock timestamps, and ``duration_ms`` are excluded so
    otherwise equivalent executions remain content-addressable across sequential,
    parallel, cached, and uncached runs. Duration remains observational metadata
    on the attempt object itself.
    """
    data = dict(_dump_json(attempt))
    data.pop("attempt_id", None)
    data.pop("started_at", None)
    data.pop("finished_at", None)
    data.pop("duration_ms", None)
    return data


def compute_attempt_id(attempt: ExecutionAttempt | dict[str, Any]) -> str:
    """Compute ``attempt_id`` from stable attempt fields."""
    return content_digest(attempt_digest_input(attempt))


def compute_raw_execution_digests(raw: RawBackendExecution) -> dict[str, str]:
    """Compute stdout/stderr/raw_result digests for a raw execution."""
    digests: dict[str, str] = {}
    if raw.stdout is not None:
        digests["stdout_digest"] = content_digest(raw.stdout)
    if raw.stderr is not None:
        digests["stderr_digest"] = content_digest(raw.stderr)
    digests["raw_result_digest"] = content_digest(raw.raw_result)
    return digests
