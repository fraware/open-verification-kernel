"""GitHub event metadata extraction.

These helpers parse the JSON event payload exposed to GitHub Actions through
`GITHUB_EVENT_PATH`. They do not call the GitHub API. API-backed branch
protection and required-check collection belongs to a later Sprint 2 step.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GitHubEventMetadata:
    """Metadata extracted from a GitHub event payload."""

    repository: str = "unknown/repo"
    head_sha: str = "unknown"
    base_sha: str | None = None
    pull_request_number: int | None = None
    actor_login: str = "unknown"
    actor_type: str = "unknown"
    event_name: str = "unknown"


def _repository_full_name(event: dict[str, Any]) -> str:
    repo = event.get("repository", {})
    if isinstance(repo, dict) and repo.get("full_name"):
        return str(repo["full_name"])
    return "unknown/repo"


def _actor_login(event: dict[str, Any]) -> str:
    sender = event.get("sender", {})
    if isinstance(sender, dict) and sender.get("login"):
        return str(sender["login"])
    return "unknown"


def _actor_type(event: dict[str, Any]) -> str:
    sender = event.get("sender", {})
    if isinstance(sender, dict) and sender.get("type"):
        return str(sender["type"])
    return "unknown"


def extract_github_event_metadata(event: dict[str, Any]) -> GitHubEventMetadata:
    """Extract OVK-relevant metadata from a GitHub event payload."""
    pull_request = event.get("pull_request")
    if isinstance(pull_request, dict):
        head = pull_request.get("head", {}) if isinstance(pull_request.get("head"), dict) else {}
        base = pull_request.get("base", {}) if isinstance(pull_request.get("base"), dict) else {}
        return GitHubEventMetadata(
            repository=_repository_full_name(event),
            head_sha=str(head.get("sha", "unknown")),
            base_sha=str(base.get("sha")) if base.get("sha") else None,
            pull_request_number=int(pull_request["number"]) if pull_request.get("number") else None,
            actor_login=_actor_login(event),
            actor_type=_actor_type(event),
            event_name="pull_request",
        )

    return GitHubEventMetadata(
        repository=_repository_full_name(event),
        head_sha=str(event.get("after", event.get("head_sha", "unknown"))),
        base_sha=str(event.get("before")) if event.get("before") else None,
        pull_request_number=None,
        actor_login=_actor_login(event),
        actor_type=_actor_type(event),
        event_name=str(event.get("action", "unknown")),
    )


def load_github_event_metadata(path: Path | None) -> GitHubEventMetadata:
    """Load metadata from a GitHub event payload path.

    If no path is provided, return unknown metadata rather than guessing.
    """
    if path is None:
        return GitHubEventMetadata()
    event = json.loads(path.read_text(encoding="utf-8"))
    return extract_github_event_metadata(event)


def metadata_to_self_protection_defaults(metadata: GitHubEventMetadata) -> dict[str, Any]:
    """Convert GitHub metadata into OVK self-protection metadata defaults."""
    return {
        "actor_type": "ai_agent" if "bot" in metadata.actor_login.lower() else "unknown",
        "agent_id": metadata.actor_login,
        "task": f"github_event:{metadata.event_name}",
    }
