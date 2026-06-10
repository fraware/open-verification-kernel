#!/usr/bin/env python
"""Emit a GitHub check run from an OVK evidence bundle."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from ovk.core.github_check import build_check_run_payload
from ovk.core.json_io import read_json_file
from ovk.core.models import EvidenceBundle


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit a GitHub check run for OVK results")
    parser.add_argument("--evidence", type=Path, default=Path("ovk-evidence.json"))
    parser.add_argument("--markdown", type=Path, default=Path("ovk-pr-comment.md"))
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--head-sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--api-base", default="https://api.github.com")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def _post_check_run(api_base: str, repo: str, token: str, payload: dict) -> bool:
    url = f"{api_base.rstrip('/')}/repos/{repo}/check-runs"
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return 200 <= response.status < 300
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return False


def main() -> int:
    args = parse_args()
    if not args.evidence.exists():
        print(f"evidence bundle not found: {args.evidence}")
        return 0

    bundle = EvidenceBundle.model_validate(read_json_file(args.evidence))
    markdown_summary = args.markdown.read_text(encoding="utf-8") if args.markdown.exists() else None
    head_sha = args.head_sha or str(bundle.subject.get("head_sha", ""))
    if not head_sha:
        print("missing head SHA; skipping GitHub check emission")
        return 0

    payload = build_check_run_payload(bundle, head_sha=head_sha, markdown_summary=markdown_summary)
    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return 0

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token or not args.repo:
        print("missing GITHUB_TOKEN or repo; skipping GitHub check emission")
        return 0

    if _post_check_run(args.api_base, args.repo, token, payload):
        print(f"emitted GitHub check run with conclusion {payload['conclusion']}")
        return 0
    print("failed to emit GitHub check run")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
