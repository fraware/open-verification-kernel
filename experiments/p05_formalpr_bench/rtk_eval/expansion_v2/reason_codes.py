"""Frozen exclusion reason codes for expansion_v2 census retention.

Every FIRST_PARENT transition that is not admitted must retain one of these
codes (or a documented extension registered in a future freeze amendment).
Unknown codes fail interface tests.
"""

from __future__ import annotations

from enum import Enum
from typing import FrozenSet


class ExclusionReasonCode(str, Enum):
    """Closed set of census exclusion reasons for v2."""

    ROOT_COMMIT_NO_PARENT = "ROOT_COMMIT_NO_PARENT"
    BEYOND_CUTOFF = "BEYOND_CUTOFF"
    HISTORY_RULE_VIOLATION = "HISTORY_RULE_VIOLATION"
    MISSING_SOURCE_OR_TARGET_SHA = "MISSING_SOURCE_OR_TARGET_SHA"
    EMPTY_CHANGED_PATHS_NOT_ELIGIBLE = "EMPTY_CHANGED_PATHS_NOT_ELIGIBLE"
    NO_GOVERNED_ARTIFACT_SURFACE = "NO_GOVERNED_ARTIFACT_SURFACE"
    ADAPTER_NOT_YET_IMPLEMENTED = "ADAPTER_NOT_YET_IMPLEMENTED"
    ADAPTER_DECLARED_INELIGIBLE = "ADAPTER_DECLARED_INELIGIBLE"
    SOURCE_SIDE_RULE_EXCLUSION = "SOURCE_SIDE_RULE_EXCLUSION"
    OPERATIONAL_CHECKOUT_FAILURE = "OPERATIONAL_CHECKOUT_FAILURE"


EXCLUSION_REASON_CODES: FrozenSet[str] = frozenset(
    code.value for code in ExclusionReasonCode
)


def is_known_exclusion_reason(code: str | None) -> bool:
    if code is None:
        return False
    return code in EXCLUSION_REASON_CODES


def require_known_exclusion_reason(code: str) -> str:
    if not is_known_exclusion_reason(code):
        raise ValueError(f"unknown expansion_v2 exclusion reason code: {code!r}")
    return code
