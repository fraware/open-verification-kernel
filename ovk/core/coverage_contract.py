"""Coverage qualification for authoritative routing.

Adapters may know whether they can *execute* an abstraction, but the router owns
the stronger question: whether that abstraction is complete enough to authorize
a required primary in strict/enforced mode. These propositions must not share one
boolean.
"""

from __future__ import annotations

from dataclasses import dataclass

from ovk.core.backend_registry import BackendRegistry
from ovk.core.execution_models import (
    BackendCapabilityAssessment,
    ExecutionContext,
    VerificationObligation,
)


@dataclass(frozen=True)
class CoverageQualification:
    """Authorization-relevant interpretation of obligation coverage."""

    can_execute: bool
    can_produce_advisory_evidence: bool
    can_be_required_primary: bool
    can_support_strict_allow: bool
    reason: str


def qualify_coverage(
    obligation: VerificationObligation,
    assessment: BackendCapabilityAssessment,
    *,
    enforced: bool,
) -> CoverageQualification:
    """Separate executable coverage from strict authorization coverage."""
    executable = bool(
        assessment.material_requirements_met
        and assessment.support not in {"unsupported", "unavailable"}
    )
    adapter_accepts = bool(assessment.coverage_requirements_met)
    complete = obligation.coverage.status == "complete"
    unsupported = bool(obligation.coverage.unsupported_constructs)

    if not executable:
        return CoverageQualification(
            can_execute=False,
            can_produce_advisory_evidence=False,
            can_be_required_primary=False,
            can_support_strict_allow=False,
            reason="backend cannot execute the supplied materials",
        )

    if enforced and (not complete or unsupported):
        details = [f"coverage={obligation.coverage.status}"]
        if unsupported:
            details.append("unsupported_constructs_present")
        return CoverageQualification(
            can_execute=True,
            can_produce_advisory_evidence=True,
            can_be_required_primary=False,
            can_support_strict_allow=False,
            reason="; ".join(details) + "; incomplete coverage cannot authorize strict primary",
        )

    primary = adapter_accepts and (complete if enforced else True)
    return CoverageQualification(
        can_execute=True,
        can_produce_advisory_evidence=True,
        can_be_required_primary=primary,
        can_support_strict_allow=primary and complete and not unsupported,
        reason=(
            "complete coverage satisfies strict primary contract"
            if primary and complete
            else "coverage is executable but not sufficient for strict allow"
        ),
    )


class CoverageContractRegistry:
    """Registry view that applies router-level coverage authorization semantics."""

    def __init__(self, registry: BackendRegistry, *, enforced: bool) -> None:
        self._registry = registry
        self._enforced = enforced

    def backend_ids(self):
        return self._registry.backend_ids()

    def candidates(
        self,
        obligation: VerificationObligation,
        context: ExecutionContext,
    ) -> list[BackendCapabilityAssessment]:
        assessments = self._registry.candidates(obligation, context)
        qualified: list[BackendCapabilityAssessment] = []
        for assessment in assessments:
            coverage = qualify_coverage(
                obligation,
                assessment,
                enforced=self._enforced,
            )
            reasons = list(assessment.reasons)
            reasons.append(f"coverage_contract:{coverage.reason}")
            qualified.append(
                assessment.model_copy(
                    update={
                        "coverage_requirements_met": coverage.can_be_required_primary,
                        "reasons": reasons,
                    }
                )
            )
        return qualified
