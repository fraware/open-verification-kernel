#!/usr/bin/env python
"""Post or update an OVK Markdown report as a pull-request comment.

This script is opt-in. If required environment variables or PR metadata are
missing, it exits successfully after explaining that no comment was posted.
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ovk.core.github_event import load_github_event_metadata
from ovk.core.pr_comment import find_existing_ovk_comment, with_ovk_marker


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Post OVK PR comment")
    parser.add_argument("--markdown", type=Path, default=Path("ovk-pr-comment.md"))
    parser.add_argument("--event", type=Path, default=None)
    parser.add_argument("--api-base", default="https://api.github.com")
    return parser.parse_args()


def _request_json(url: str, api_token: str) -> list[dict[str, Any]] | None:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {api_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return payload if isinstance(payload, list) else None
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def _send_comment(url: str, api_token: str, body: str, method: str) -> bool:
    payload = json.dumps({"body": body}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10):
            return True
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return False


def main() -> int:
    args = parse_args()
    event_path = args.event or Path(os.environ.get("GITHUB_EVENT_PATH", ""))
    if not event_path.exists():
        print("OVK comment not posted: GitHub event payload unavailable.")
        return 0

    metadata = load_github_event_metadata(event_path)
    if metadata.pull_request_number is None:
        print("OVK comment not posted: event is not a pull request.")
        return 0

    api_token = os.environ.get("GITHUB_TOKEN")
    if not api_token:
        print("OVK comment not posted: GITHUB_TOKEN unavailable.")
        return 0

    body = with_ovk_marker(args.markdown.read_text(encoding="utf-8"))
    base_url = f"{args.api_base.rstrip('/')}/repos/{metadata.repository}"
    comments_url = f"{base_url}/issues/{metadata.pull_request_number}/comments"
    comments = _request_json(comments_url, api_token) or []
    existing_comment_id = find_existing_ovk_comment(comments)

    if existing_comment_id is not None:
        update_url = f"{base_url}/issues/comments/{existing_comment_id}"
        if _send_comment(update_url, api_token, body, method="PATCH"):
            print("OVK PR comment updated.")
        else:
            print("OVK comment not updated: GitHub API request failed.")
        return 0

    if _send_comment(comments_url, api_token, body, method="POST"):
        print("OVK PR comment posted.")
    else:
        print("OVK comment not posted: GitHub API request failed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
