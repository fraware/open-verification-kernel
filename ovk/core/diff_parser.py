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


def is_unified_diff(text: str) -> bool:
    """Return True when text looks like a unified diff."""
    stripped = text.strip()
    if not stripped:
        return False
    return stripped.startswith("diff --git ") or "\ndiff --git " in text or "+++ b/" in text


def extract_post_images(diff_text: str) -> dict[str, str]:
    """Reconstruct post-change file contents from unified diff text.

    Each returned value approximates the ``b/`` side of the diff by applying
    hunk additions and deletions. This is sufficient for workflow and config
    analysis when the full post-image is not available on disk.
    """
    images: dict[str, str] = {}
    current_path: str | None = None
    current_lines: list[str] = []

    def flush() -> None:
        nonlocal current_path, current_lines
        if current_path is not None:
            images[current_path] = "\n".join(current_lines)
            if current_lines:
                images[current_path] += "\n"
        current_path = None
        current_lines = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            flush()
            parts = line.split()
            if len(parts) >= 4:
                candidate = _normalize_diff_path(parts[3])
                current_path = None if candidate == "/dev/null" else candidate
            continue
        if line.startswith("+++ "):
            candidate = _normalize_diff_path(line[4:])
            if candidate != "/dev/null":
                current_path = candidate
            continue
        if current_path is None:
            continue
        if line.startswith("@@ "):
            continue
        if line.startswith("\\ No newline"):
            continue
        if line.startswith("+") or line.startswith(" "):
            current_lines.append(line[1:])
        elif line.startswith("-"):
            continue

    flush()
    return images


def reconstruct_post_image(diff_text: str, path: str) -> str | None:
    """Return the reconstructed post-image for one path, if present in the diff."""
    normalized = _normalize_diff_path(path)
    return extract_post_images(diff_text).get(normalized)
