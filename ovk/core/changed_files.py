"""Changed-file ingestion helpers for the Sprint 1 runner."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.core.diff_parser import extract_changed_paths


def load_changed_files(path: Path) -> list[str]:
    """Load changed files from JSON, newline text, or unified diff.

    Supported formats:
    - JSON list of paths;
    - JSON object with `changed_files`;
    - newline-delimited paths;
    - unified diff text.
    """
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        return []

    if stripped.startswith("[") or stripped.startswith("{"):
        data = json.loads(stripped)
        if isinstance(data, list):
            return [str(item) for item in data]
        if isinstance(data, dict):
            files = data.get("changed_files", [])
            return [str(item) for item in files] if isinstance(files, list) else []

    if "diff --git " in text or "+++ b/" in text:
        return extract_changed_paths(text)

    return [line.strip() for line in text.splitlines() if line.strip()]
