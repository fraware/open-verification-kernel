"""Adapter interfaces for Open Verification Kernel.

Adapters connect verification intents to concrete tools while preserving
assumptions, limits, and result semantics. The interface is intentionally small
so OPA, Z3, Kani, TLA+, Dafny, Verus, Lean, Cedar, CBMC, Alloy, and future
backends can plug into the same kernel contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ovk.core.models import VerificationEvidence, VerificationIntent


@dataclass(frozen=True)
class CapabilityScore:
    """Router-facing score for a backend on a specific intent."""

    score: float
    reason: str


@dataclass(frozen=True)
class ProofObligation:
    """Backend-specific task compiled from a verification intent."""

    obligation_id: str
    intent_id: str
    backend: str
    query_polarity: str
    payload: dict[str, Any]
    assumptions: list[str]


@dataclass(frozen=True)
class VerificationBudget:
    """Operational budget for a backend call."""

    timeout_seconds: int = 30
    max_memory_mb: int = 512


class VerificationAdapter(Protocol):
    """Protocol implemented by OVK backend adapters."""

    def manifest(self) -> dict[str, Any]:
        """Return the backend capability manifest."""
        ...

    def can_handle(
        self,
        *,
        intent: VerificationIntent,
        context: dict[str, Any],
        change: dict[str, Any],
    ) -> CapabilityScore:
        """Return a score and explanation for routing."""
        ...

    def compile(
        self,
        *,
        intent: VerificationIntent,
        context: dict[str, Any],
        change: dict[str, Any],
    ) -> ProofObligation:
        """Compile an intent into a backend-specific obligation."""
        ...

    def run(
        self,
        *,
        obligation: ProofObligation,
        budget: VerificationBudget,
    ) -> dict[str, Any]:
        """Run the backend-specific obligation."""
        ...

    def normalize(
        self,
        *,
        raw: dict[str, Any],
        obligation: ProofObligation,
    ) -> VerificationEvidence:
        """Normalize backend output into OVK evidence."""
        ...
