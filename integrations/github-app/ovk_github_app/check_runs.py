"""Idempotent Check Run helpers aligned with PR6 emit patterns."""

from __future__ import annotations

from typing import Any

# Prefer the kernel helper when available so App and Action stay aligned.
try:
    from ovk.core.github_check import CHECK_NAME, check_run_external_id
except ImportError:  # pragma: no cover - standalone alpha checkout

    def check_run_external_id(*, repo: str, head_sha: str) -> str:
        return f"ovk:{repo}:{head_sha}"

    CHECK_NAME = "Open Verification Kernel"


def app_check_run_external_id(*, repo: str, head_sha: str) -> str:
    """Stable external_id per head SHA — same format as the composite Action."""
    return check_run_external_id(repo=repo, head_sha=head_sha)


def build_check_run_update_payload(
    *,
    repo: str,
    head_sha: str,
    conclusion: str,
    title: str,
    summary: str,
    status: str = "completed",
) -> dict[str, Any]:
    """Build a check-run create/update body with idempotent ``external_id``."""
    if not head_sha or not str(head_sha).strip():
        raise ValueError("head_sha is required for check-run updates")
    if not repo or not str(repo).strip():
        raise ValueError("repo is required for check-run updates")
    return {
        "name": CHECK_NAME,
        "head_sha": str(head_sha).strip(),
        "external_id": app_check_run_external_id(repo=str(repo).strip(), head_sha=str(head_sha).strip()),
        "status": status,
        "conclusion": conclusion,
        "output": {
            "title": title[:255],
            "summary": summary[:65535],
        },
    }
