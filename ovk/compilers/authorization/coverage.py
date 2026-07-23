"""Coverage confidence policy for authorization compilers.

Confidence is not an unexplained heuristic. It is derived from explicit,
documented factors:

* ``complete`` requires base+head materials, zero unsupported constructs on
  extracted routes, and every route marked ``supported``.
* ``partial`` is used when materials exist but dynamic/unsupported constructs
  were observed, or when policy explicitly accepts partial coverage.
* ``unknown`` is used when base or head materials are missing.

Strict allow requires ``complete`` coverage, or ``partial`` only when
``accept_partial_coverage`` is explicitly enabled by policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ovk.compilers.authorization.ir import AuthorizationIR
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.core.execution_models import AbstractionCoverage

CoverageStatus = Literal["complete", "partial", "unknown"]


@dataclass(frozen=True)
class CoveragePolicy:
    """Explicit policy controlling when partial coverage may allow."""

    accept_partial_coverage: bool = False
    min_complete_confidence: float = 1.0
    partial_confidence_cap: float = 0.6
    unknown_confidence: float = 0.0


def assess_coverage(
    ir: AuthorizationIR,
    materials: AuthMaterials,
    *,
    policy: CoveragePolicy | None = None,
) -> AbstractionCoverage:
    """Compute documented coverage for an authorization IR."""
    policy = policy or CoveragePolicy()
    warnings = list(ir.warnings)
    unsupported = list(ir.unsupported_constructs)
    for route in ir.routes:
        unsupported.extend(route.unsupported_constructs)
        if route.support != "supported":
            unsupported.append(f"route:{route.path}:{route.support}")

    extracted = len(ir.routes)
    if not materials.has_base() or not materials.has_head():
        if not materials.has_base():
            warnings.append("base materials missing; before protections cannot be reconstructed")
        if not materials.has_head():
            warnings.append("head materials missing; after protections cannot be reconstructed")
        return AbstractionCoverage(
            status="unknown",
            confidence=policy.unknown_confidence,
            extracted_elements=extracted,
            expected_elements=None,
            unsupported_constructs=sorted(set(unsupported)),
            warnings=warnings,
        )

    dynamic_or_unsupported = bool(unsupported) or any(route.support != "supported" for route in ir.routes)
    if extracted == 0:
        return AbstractionCoverage(
            status="unknown",
            confidence=policy.unknown_confidence,
            extracted_elements=0,
            expected_elements=None,
            unsupported_constructs=sorted(set(unsupported)),
            warnings=warnings + ["no routes extracted"],
        )

    if dynamic_or_unsupported:
        return AbstractionCoverage(
            status="partial",
            confidence=min(policy.partial_confidence_cap, 0.5 if unsupported else 0.6),
            extracted_elements=extracted,
            expected_elements=extracted,
            unsupported_constructs=sorted(set(unsupported)),
            warnings=warnings + ["dynamic or unsupported constructs reduce coverage"],
        )

    return AbstractionCoverage(
        status="complete",
        confidence=policy.min_complete_confidence,
        extracted_elements=extracted,
        expected_elements=extracted,
        unsupported_constructs=[],
        warnings=warnings,
    )


def strict_allow_permitted(coverage: AbstractionCoverage, policy: CoveragePolicy | None = None) -> bool:
    """Return whether strict allow is permitted under coverage policy."""
    policy = policy or CoveragePolicy()
    if coverage.status == "complete":
        return True
    if coverage.status == "partial" and policy.accept_partial_coverage:
        return True
    return False
