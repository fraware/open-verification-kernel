"""Unified-diff parsing utilities.

The parser is intentionally small and dependency-free. It extracts changed paths
from unified diff text so OVK can move from fixture-based demos toward real PR
analysis.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ChangedFile:
    """A file path observed in a diff."""

    path: str
    status: str = "modified"


def _normalize_diff_path(path: str) -> str:
    path = path.strip()
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def extract_changed_files(diff_text: str) -> list[ChangedFile]:
    """Extract changed files from unified diff text.

    Supports standard lines such as:

    ```text
    diff --git a/foo.py b/foo.py
    --- a/foo.py
    +++ b/foo.py
    ```
    """
    files: list[ChangedFile] = []
    seen: set[str] = set()

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                path = _normalize_diff_path(parts[3])
                if path != "/dev/null" and path not in seen:
                    files.append(ChangedFile(path=path))
                    seen.add(path)
        elif line.startswith("+++ "):
            path = _normalize_diff_path(line[4:])
            if path != "/dev/null" and path not in seen:
                files.append(ChangedFile(path=path))
                seen.add(path)

    return files


def extract_changed_paths(diff_text: str) -> list[str]:
    """Return only changed paths from unified diff text."""
    return [item.path for item in extract_changed_files(diff_text)]
