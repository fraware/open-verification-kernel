"""Shared adapter contract types for external backends."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


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
    """Human-readable explanation of a verification result."""

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
