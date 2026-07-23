"""Shared adapter contract types for OVK backends.

The authoritative control-plane protocol is ``BackendAdapter``. Legacy
``ExternalAdapter`` types remain for wave1/wave2 optional backends until those
adapters are migrated onto the typed obligation path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ovk.core.execution_models import (
    BackendCapabilityAssessment,
    BackendCapabilityManifest,
    BackendEnvironmentFingerprint,
    BackendObligation,
    ExecutionBudget,
    HumanExplanation as TypedHumanExplanation,
    NormalizedBackendResult,
    RawBackendExecution,
    RoutingDecision,
    VerificationObligation,
    ExecutionContext,
)

# Re-export the typed explanation used by BackendAdapter for callers.
HumanExplanationTyped = TypedHumanExplanation


# ---------------------------------------------------------------------------
# Legacy external-adapter contract (wave backends)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityScore:
    """Score describing how well a backend can handle an intent."""

    backend: str
    score: float
    reason: str


@dataclass(frozen=True)
class ProofObligation:
    """Compiled proof obligation for a backend."""

    backend: str
    intent_id: str
    input: dict[str, Any]
    input_language: str
    scope: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RawBackendResult:
    """Raw result from a backend execution step."""

    backend: str
    status: str
    counterexamples: list[dict[str, Any]] = field(default_factory=list)
    used_native_binary: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VerificationResult:
    """Normalized verification result from an adapter."""

    status: str
    merge_recommendation: str
    counterexamples: list[dict[str, Any]] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    limits: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class HumanExplanation:
    """Human-readable explanation of a verification result (legacy dataclass)."""

    summary: str
    repair_hint: str
    failure_mode: str | None = None


class ExternalAdapter(Protocol):
    """Adapter contract surface for external verification backends."""

    def manifest(self) -> dict[str, Any]: ...

    def can_handle(self, *, intent: dict[str, Any], context: dict[str, Any]) -> CapabilityScore: ...

    def compile(self, *, intent: dict[str, Any], change: dict[str, Any]) -> ProofObligation: ...

    def run(self, obligation: ProofObligation) -> RawBackendResult: ...

    def normalize(self, raw: RawBackendResult, obligation: ProofObligation) -> VerificationResult: ...

    def explain(self, result: VerificationResult) -> HumanExplanation: ...


# ---------------------------------------------------------------------------
# Authoritative control-plane adapter protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class BackendAdapter(Protocol):
    """Central kernel adapter protocol for registered verification backends.

    Adapters declare capability, assess fit, compile backend-specific obligations,
    fingerprint the execution environment, run under budget, normalize results,
    and explain outcomes. Lane wrappers and native backends share this contract.
    """

    backend_id: str
    adapter_id: str
    adapter_version: str

    def manifest(self) -> BackendCapabilityManifest: ...

    def can_handle(
        self,
        obligation: VerificationObligation,
        context: ExecutionContext,
    ) -> BackendCapabilityAssessment: ...

    def compile(
        self,
        obligation: VerificationObligation,
        routing: RoutingDecision,
    ) -> BackendObligation: ...

    def fingerprint(
        self,
        backend_obligation: BackendObligation,
    ) -> BackendEnvironmentFingerprint: ...

    def run(
        self,
        backend_obligation: BackendObligation,
        budget: ExecutionBudget,
    ) -> RawBackendExecution: ...

    def normalize(
        self,
        raw: RawBackendExecution,
        backend_obligation: BackendObligation,
    ) -> NormalizedBackendResult: ...

    def explain(
        self,
        result: NormalizedBackendResult,
    ) -> TypedHumanExplanation: ...
