#!/usr/bin/env python
"""Collect branch protection metadata for OVK.

This script uses the repository and branch values supplied by GitHub Actions.
When metadata cannot be collected, it writes an empty JSON object so OVK treats
the required-check state as unknown.
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect OVK branch metadata")
    parser.add_argument("--repository", default=None)
    parser.add_argument("--branch", default=None)
    parser.add_argument("--output", type=Path, default=Path("ovk-required-checks.json"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = config_from_environment(repository=args.repository, branch=args.branch)
    payload = {}

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
