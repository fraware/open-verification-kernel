"""Load infrastructure exposure policy from JSON-like data."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from ovk.adapters.infra.policy import DEFAULT_BLOCKED_SENSITIVITIES, InfraExposurePolicy
from ovk.core.schema_validation import require_schema_valid
from ovk.paths import schema_path


VALID_SENSITIVITY = {"public", "internal", "confidential", "restricted"}


def policy_from_data(data: dict[str, Any]) -> InfraExposurePolicy:
    """Build an infrastructure exposure policy from JSON-like data.

    Expected shape:

    {
      "blocked_public_sensitivities": ["confidential", "restricted"]
    }
    """
    values = data.get("blocked_public_sensitivities", list(DEFAULT_BLOCKED_SENSITIVITIES))
    if not isinstance(values, list):
        raise ValueError("blocked_public_sensitivities must be a list")
    normalized = frozenset(str(value) for value in values)
    invalid = normalized - VALID_SENSITIVITY
    if invalid:
        raise ValueError(f"invalid sensitivity levels: {sorted(invalid)}")
    return InfraExposurePolicy(blocked_public_sensitivities=normalized)


POLICY_SCHEMA_PATH = schema_path("infrastructure.policy.schema.json")


def load_policy(path: Path | None) -> InfraExposurePolicy:
    """Load an infrastructure exposure policy from disk, or return the default."""
    if path is None:
        return InfraExposurePolicy()
    data = json.loads(path.read_text(encoding="utf-8"))
    if POLICY_SCHEMA_PATH.exists():
        require_schema_valid(
            data,
            json.loads(POLICY_SCHEMA_PATH.read_text(encoding="utf-8")),
            context="infrastructure policy",
        )
    return policy_from_data(data)
