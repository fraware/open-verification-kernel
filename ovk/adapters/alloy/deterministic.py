"""Deterministic Alloy oracle used when the Alloy binary is unavailable."""

from __future__ import annotations

from typing import Any

from ovk.adapters.wave2_oracle import evaluate_bounded_model


def evaluate_alloy_input(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    return evaluate_bounded_model(data, failure_mode="alloy_counterexample_found")
