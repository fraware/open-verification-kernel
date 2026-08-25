"""Coverage qualification for authoritative routing.

Adapters may know whether they can *execute* an abstraction, but the router owns
the stronger question: whether that abstraction is complete enough to authorize
a required primary in strict/enforced mode. These propositions must not share one
boolean.
"""

from __future__ import annotations

from dataclasses import dataclass

from ovk.compilers.authorization import CoveragePolicy, strict_allow_permitted
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
    coverage_policy: CoveragePolicy | None = None,
) -> CoverageQualification:
    """Separate executable coverage from strict authorization coverage."""
    executable = bool(
        assessment.material_requirements_met
        and assessment.support not in {"unsupported", "unavailable"}
    )
    adapter_accepts = bool(assessment.coverage_requirements_met)
    policy = coverage_policy or CoveragePolicy()
    strict_coverage_ok = strict_allow_permitted(obligation.coverage, policy)

    if not executable:
        return CoverageQualification(
            can_execute=False,
            can_produce_advisory_evidence=False,
            can_be_required_primary=False,
            can_support_strict_allow=False,
            reason="backend cannot execute the supplied materials",
        )

    if enforced and not strict_coverage_ok:
        details = [f"coverage={obligation.coverage.status}"]
        if obligation.coverage.unsupported_constructs:
            details.append("unsupported_constructs_present")
        return CoverageQualification(
            can_execute=True,
            can_produce_advisory_evidence=True,
            can_be_required_primary=False,
            can_support_strict_allow=False,
            reason="; ".join(details) + "; coverage policy does not authorize strict primary",
        )

    primary = adapter_accepts and (strict_coverage_ok if enforced else True)
    if primary and obligation.coverage.status == "complete":
        reason = "complete coverage satisfies strict primary contract"
    elif primary and enforced:
        reason = "explicit obligation-bound policy accepts partial coverage for strict primary"
    else:
        reason = "coverage is executable but not sufficient for strict allow"

    return CoverageQualification(
        can_execute=True,
        can_produce_advisory_evidence=True,
        can_be_required_primary=primary,
        can_support_strict_allow=primary and strict_coverage_ok,
        reason=reason,
    )


class CoverageContractRegistry:
    """Registry view that applies router-level coverage authorization semantics."""

    def __init__(
        self,
        registry: BackendRegistry,
        *,
        enforced: bool,
        coverage_policy: CoveragePolicy | None = None,
    ) -> None:
        self._registry = registry
        self._enforced = enforced
        self._coverage_policy = coverage_policy or CoveragePolicy()

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
                coverage_policy=self._coverage_policy,
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
