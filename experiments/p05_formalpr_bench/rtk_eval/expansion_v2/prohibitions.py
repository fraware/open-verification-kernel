"""Prohibition guards for expansion_v2 adapters.

Adapters must never invoke RTK, target-revision validators, oracle labels, or
unblinded information. These helpers encode that contract for tests and for
runtime refusal stubs.
"""

from __future__ import annotations

from typing import Final

PROHIBITED_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        "rtk_prediction",
        "rtk_import",
        "target_revision_validator",
        "oracle_label_read",
        "unblinded_information",
        "tier_a_attestation_substitution",
        "tier_b_promotion_to_tier_a",
        "cardinality_tuning",
        "candidate_list_mutation",
        "v0_artifact_mutation",
    }
)

PROHIBITED_IMPORT_NAME_FRAGMENTS: Final[tuple[str, ...]] = (
    "rtk_predict",
    "run_rtk",
    "oracle_label",
    "unblind",
)


class AdapterProhibitionError(RuntimeError):
    """Raised when an adapter attempts a forbidden capability."""


def assert_capability_allowed(capability: str) -> None:
    if capability in PROHIBITED_CAPABILITIES:
        raise AdapterProhibitionError(
            f"expansion_v2 adapter prohibited capability: {capability}"
        )


def refuse_prohibited(capability: str) -> None:
    """Explicit refusal used by stubs and guards."""
    assert_capability_allowed(capability)
