"""Required-check metadata helpers.

The runner treats missing required-check metadata as an honest unknown. This
module normalizes metadata supplied by CI, fixtures, or a future GitHub API
collector.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _as_string_list(value: object) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        return None
    return [str(item) for item in value]


def _extract_contexts(value: object) -> list[str] | None:
    """Extract required check names from common GitHub API shapes."""
    if not isinstance(value, dict):
        return None

    required = value.get("required_status_checks", value)
    if not isinstance(required, dict):
        return None

    contexts: list[str] = []
    raw_contexts = required.get("contexts")
    if isinstance(raw_contexts, list):
        contexts.extend(str(item) for item in raw_contexts)

    raw_checks = required.get("checks")
    if isinstance(raw_checks, list):
        for item in raw_checks:
            if isinstance(item, dict) and item.get("context"):
                contexts.append(str(item["context"]))

    return contexts if contexts else None


def normalize_required_check_metadata(data: dict[str, Any]) -> dict[str, list[str] | None]:
    """Normalize explicit or GitHub-shaped required-check metadata."""
    before = _as_string_list(data.get("before_required_checks"))
    after = _as_string_list(data.get("after_required_checks"))

    if before is None:
        before = _extract_contexts(data.get("before_branch_protection"))
    if after is None:
        after = _extract_contexts(data.get("after_branch_protection"))

    return {
        "before_required_checks": before,
        "after_required_checks": after,
    }


def load_required_check_metadata(path: Path | None) -> dict[str, list[str] | None]:
    """Load before/after required-check metadata.

    Accepted JSON shapes:

    {
      "before_required_checks": ["unit-tests", "ovk-verify"],
      "after_required_checks": ["unit-tests", "ovk-verify"]
    }

    or:

    {
      "before_branch_protection": {"required_status_checks": {"contexts": ["ovk-verify"]}},
      "after_branch_protection": {"required_status_checks": {"contexts": ["ovk-verify"]}}
    }
    """
    if path is None:
        return {"before_required_checks": None, "after_required_checks": None}
    data = json.loads(path.read_text(encoding="utf-8"))
    return normalize_required_check_metadata(data)
