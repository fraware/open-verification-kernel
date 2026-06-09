"""PR comment helpers for OVK reports."""

from __future__ import annotations

from typing import Any


OVK_COMMENT_MARKER = "OVK_REPORT_COMMENT_V1"


def with_ovk_marker(markdown: str) -> str:
    """Ensure a Markdown report contains the OVK marker."""
    if markdown.startswith(OVK_COMMENT_MARKER):
        return markdown
    return f"{OVK_COMMENT_MARKER}\n\n{markdown}"


def find_existing_ovk_comment(comments: list[dict[str, Any]]) -> int | None:
    """Return the first issue-comment ID that already contains the OVK marker."""
    for comment in comments:
        body = str(comment.get("body", ""))
        if OVK_COMMENT_MARKER in body and comment.get("id") is not None:
            return int(comment["id"])
    return None
