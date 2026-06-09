#!/usr/bin/env python
"""Post an OVK Markdown report as a pull-request comment.

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

from ovk.core.github_event import load_github_event_metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Post OVK PR comment")
    parser.add_argument("--markdown", type=Path, default=Path("ovk-pr-comment.md"))
    parser.add_argument("--event", type=Path, default=None)
    parser.add_argument("--api-base", default="https://api.github.com")
    return parser.parse_args()


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

    body = args.markdown.read_text(encoding="utf-8")
    url = (
        f"{args.api_base.rstrip('/')}/repos/{metadata.repository}"
        f"/issues/{metadata.pull_request_number}/comments"
    )
    payload = json.dumps({"body": body}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10):
            print("OVK PR comment posted.")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        print("OVK comment not posted: GitHub API request failed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
