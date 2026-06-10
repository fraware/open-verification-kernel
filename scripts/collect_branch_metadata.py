#!/usr/bin/env python
"""Collect branch protection metadata for OVK.

This script uses GitHub event payloads and/or GitHub Actions environment
variables. When metadata cannot be collected, it writes an empty JSON object so
OVK treats the required-check state as unknown.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ovk.core.github_api_metadata import (
    config_from_environment,
    fetch_branch_protection,
    required_checks_from_branch_protection,
)
from ovk.core.github_event import load_github_event_metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect OVK branch metadata")
    parser.add_argument("--repository", default=None)
    parser.add_argument("--branch", default=None)
    parser.add_argument("--event", type=Path, default=None, help="GitHub event payload JSON")
    parser.add_argument("--output", type=Path, default=Path("ovk-required-checks.json"))
    return parser.parse_args()


def _branch_from_event(event_path: Path | None) -> str | None:
    if event_path is None:
        return None
    metadata = load_github_event_metadata(event_path)
    if metadata.base_sha:
        return None
    pull_request = json.loads(event_path.read_text(encoding="utf-8")).get("pull_request")
    if isinstance(pull_request, dict):
        base = pull_request.get("base", {})
        if isinstance(base, dict) and base.get("ref"):
            return str(base["ref"])
    return None


def main() -> int:
    args = parse_args()
    repository = args.repository
    branch = args.branch

    if args.event is not None:
        event_metadata = load_github_event_metadata(args.event)
        if repository is None and event_metadata.repository != "unknown/repo":
            repository = event_metadata.repository
        if branch is None:
            branch = _branch_from_event(args.event)

    config = config_from_environment(repository=repository, branch=branch)
    payload: dict[str, object] = {}

    if config is not None:
        branch_protection = fetch_branch_protection(config)
        required_checks = required_checks_from_branch_protection(branch_protection)
        if required_checks is not None:
            payload = {
                "before_required_checks": required_checks,
                "after_required_checks": required_checks,
                "source": "branch_protection",
                "repository": config.repository,
                "branch": config.branch,
            }

    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if payload:
        print("OVK branch metadata collected.")
    else:
        print("OVK branch metadata unavailable; wrote empty metadata.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
