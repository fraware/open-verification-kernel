"""Optional GitHub API metadata collection.

This module is intentionally conservative. If token, repository, branch, or API
response data is unavailable, callers receive `None` and OVK must treat the
required-check state as unknown.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from ovk.core.check_metadata import normalize_required_check_metadata


@dataclass(frozen=True)
class GitHubApiConfig:
    """Configuration for GitHub API metadata collection."""

    repository: str
    branch: str
    token: str | None = None
    api_base: str = "https://api.github.com"


def branch_protection_url(config: GitHubApiConfig) -> str:
    """Return the branch protection API URL for a repository and branch."""
    owner_repo = config.repository.strip("/")
    branch = urllib.parse.quote(config.branch, safe="")
    return f"{config.api_base.rstrip('/')}/repos/{owner_repo}/branches/{branch}/protection"


def _request_json(url: str, token: str | None) -> dict[str, Any] | None:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def fetch_branch_protection(config: GitHubApiConfig) -> dict[str, Any] | None:
    """Fetch branch protection metadata, returning None when unavailable."""
    if not config.repository or not config.branch:
        return None
    return _request_json(branch_protection_url(config), config.token)


def required_checks_from_branch_protection(branch_protection: dict[str, Any] | None) -> list[str] | None:
    """Extract required checks from a GitHub branch protection response."""
    if branch_protection is None:
        return None
    normalized = normalize_required_check_metadata({"after_branch_protection": branch_protection})
    return normalized["after_required_checks"]


def config_from_environment(repository: str | None = None, branch: str | None = None) -> GitHubApiConfig | None:
    """Build API config from explicit values and GitHub Actions environment variables."""
    repo = repository or os.environ.get("GITHUB_REPOSITORY")
    selected_branch = branch or os.environ.get("GITHUB_BASE_REF") or os.environ.get("GITHUB_REF_NAME")
    if not repo or not selected_branch:
        return None
    return GitHubApiConfig(
        repository=repo,
        branch=selected_branch,
        token=os.environ.get("GITHUB_TOKEN"),
    )
