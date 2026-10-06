"""Explicit RTK reference predictor for CanonicalDecisionInput.v1.

This package is a semantics-faithful reference implementation for sealed-eval
binding. It is not the unrecovered historical Go production checker.
"""

from __future__ import annotations

try:
    from .canonicalize import compute_canonical_digest, prepare_for_canonicalization
    from .predictor import VERDICT_SPACE, predict, predict_many
except ImportError:  # pragma: no cover
    from canonicalize import compute_canonical_digest, prepare_for_canonicalization
    from predictor import VERDICT_SPACE, predict, predict_many

__all__ = [
    "VERDICT_SPACE",
    "compute_canonical_digest",
    "prepare_for_canonicalization",
    "predict",
    "predict_many",
]

IMPLEMENTATION_ID = "rtk.reference_implementation.v0"
IMPLEMENTATION_KIND = "REFERENCE_NOT_HISTORICAL_GO"
