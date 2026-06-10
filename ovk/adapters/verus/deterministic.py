"""Deterministic Verus oracle used when the Verus binary is unavailable."""

from __future__ import annotations

from typing import Any

from ovk.adapters.wave2_oracle import evaluate_proof_obligation


def evaluate_verus_input(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    return evaluate_proof_obligation(data, failure_mode="verus_proof_failed")
