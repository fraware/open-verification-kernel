"""Verus Rust proof adapter with deterministic fallback."""

from __future__ import annotations

from typing import Any

from ovk.adapters.verus.adapter import ADAPTER
from ovk.core.models import VerificationEvidence


def evaluate_verus_harness(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
) -> VerificationEvidence:
    return ADAPTER.evaluate_evidence(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
