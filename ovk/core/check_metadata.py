"""Required-check metadata helpers for Sprint 1.

The v0 runner treats missing required-check metadata as an honest unknown. This
module only normalizes metadata when it is explicitly supplied by CI, a test
fixture, or a future GitHub API collector.
"""

from __future__ import annotations

import json
from pathlib import Path


def _as_string_list(value: object) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        return None
    return [str(item) for item in value]


def load_required_check_metadata(path: Path | None) -> dict[str, list[str] | None]:
    """Load before/after required-check metadata.

    Expected JSON shape:

    {
      "before_required_checks": ["unit-tests", "ovk-verify"],
      "after_required_checks": ["unit-tests", "ovk-verify"]
    }
    """
    if path is None:
        return {"before_required_checks": None, "after_required_checks": None}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        "before_required_checks": _as_string_list(data.get("before_required_checks")),
        "after_required_checks": _as_string_list(data.get("after_required_checks")),
    }
